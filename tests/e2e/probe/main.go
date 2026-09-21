// Command probe drives the end-to-end lab: it talks to the real ghostd binary
// over gRPC and inspects the real host (nft, sysctl, systemd, dhclient) inside
// the disposable systemd container. It runs in phases so the orchestrating
// script can reboot the container between them:
//
//	probe pre     firewall, netconfig, crash recovery and the dnsmasq takeover
//	probe post    after a container restart: everything confirmed must be back
//	probe expiry  unconfirmed takeover rolled back, by watcher and by boot
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
	pb "github.com/xaiki/ghostd/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const addr = "100.64.0.1:7443"

var failures int

func step(name string) { fmt.Printf("\n=== %s\n", name) }
func check(ok bool, format string, a ...any) {
	if ok {
		fmt.Printf("  ok:   %s\n", fmt.Sprintf(format, a...))
		return
	}
	failures++
	fmt.Printf("  FAIL: %s\n", fmt.Sprintf(format, a...))
}
func must(err error, what string) {
	if err != nil {
		fmt.Printf("  FATAL: %s: %v\n", what, err)
		os.Exit(1)
	}
}

func sh(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
func shOK(name string, args ...string) string {
	out, err := sh(name, args...)
	must(err, name+" "+strings.Join(args, " ")+": "+out)
	return out
}

// client dials a brand-new TCP connection every time, which is what the
// confirmation rule requires.
func client() (pb.HostStateClient, func()) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	must(err, "dial")
	return pb.NewHostStateClient(conn), func() { conn.Close() }
}
func rpc[T any](f func(context.Context, pb.HostStateClient) (T, error)) (T, error) {
	c, done := client()
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return f(ctx, c)
}
func apply(domain, doc string, secs int32) (string, error) {
	r, err := rpc(func(ctx context.Context, c pb.HostStateClient) (*pb.ApplyResponse, error) {
		return c.Apply(ctx, &pb.ApplyRequest{Domain: domain, DesiredStateJson: doc, DeadManSwitchSeconds: secs})
	})
	if err != nil {
		return "", err
	}
	return r.LeaseId, nil
}
func confirm(lease string) error {
	r, err := rpc(func(ctx context.Context, c pb.HostStateClient) (*pb.ConfirmResponse, error) {
		return c.Confirm(ctx, &pb.ConfirmRequest{LeaseId: lease})
	})
	if err == nil && !r.Ok {
		err = fmt.Errorf("ok=false")
	}
	return err
}
func handover(req string) (map[string]any, error) {
	r, err := rpc(func(ctx context.Context, c pb.HostStateClient) (*pb.RegistryResponse, error) {
		return c.DHCPHandover(ctx, &pb.RegistryDocument{Json: req})
	})
	if err != nil {
		return nil, err
	}
	var out map[string]any
	return out, json.Unmarshal([]byte(r.Json), &out)
}
func registry() map[string]any {
	r, err := rpc(func(ctx context.Context, c pb.HostStateClient) (*pb.RegistryResponse, error) {
		return c.GetRegistry(ctx, &pb.RegistryRequest{})
	})
	must(err, "GetRegistry")
	var out map[string]any
	must(json.Unmarshal([]byte(r.Json), &out), "registry json")
	return out
}
func phase() string {
	j, err := handover(`{"action":"status"}`)
	must(err, "handover status")
	p, _ := j["Phase"].(string)
	if p == "" {
		p, _ = j["phase"].(string)
	}
	return p
}

func eventually(what string, timeout time.Duration, f func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f() {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	check(false, "timed out waiting for %s", what)
	return false
}
func waitReady() {
	ok := eventually("ghostd to serve GetState", 90*time.Second, func() bool {
		_, err := rpc(func(ctx context.Context, c pb.HostStateClient) (*pb.State, error) {
			return c.GetState(ctx, &pb.GetStateRequest{})
		})
		return err == nil
	})
	if !ok {
		out, _ := sh("journalctl", "-u", "ghostd.service", "-n", "40", "--no-pager")
		fmt.Println(out)
		os.Exit(1)
	}
}
func restartGhostd(kill bool) {
	if kill {
		shOK("systemctl", "kill", "-s", "KILL", "ghostd.service")
	} else {
		shOK("systemctl", "stop", "ghostd.service")
		shOK("systemctl", "start", "ghostd.service")
	}
	time.Sleep(1 * time.Second)
	waitReady()
}

func nft() string {
	out, err := sh("nft", "list", "table", "inet", "stack_ghostd")
	if err != nil {
		return ""
	}
	return out
}

const legacyUnit = "dnsmasq@ghostd-lab.service"

var boundRe = regexp.MustCompile(`DHCPACK of (\S+) from (\S+)`)

// dhcp runs ISC dhclient in a client namespace and returns the acked address.
func dhcp(ns string) string {
	pid, lease := "/tmp/"+ns+".pid", "/tmp/"+ns+".leases"
	if raw, err := os.ReadFile(pid); err == nil {
		exec.Command("kill", strings.TrimSpace(string(raw))).Run()
		time.Sleep(200 * time.Millisecond)
	}
	out, err := sh("nsenter", "--net=/run/netns/"+ns, "--", "dhclient", "-4", "-1", "-v", "-lf", lease, "-pf", pid, ns+"p")
	m := boundRe.FindAllStringSubmatch(out, -1)
	if err != nil || len(m) == 0 {
		fmt.Println(out)
		return ""
	}
	return m[len(m)-1][1]
}
func soa(network string) bool {
	q := new(dns.Msg)
	q.SetQuestion("lab.home.arpa.", dns.TypeSOA)
	r, _, err := (&dns.Client{Net: network, Timeout: 2 * time.Second}).Exchange(q, "10.77.0.1:53")
	return err == nil && r.Authoritative && len(r.Answer) > 0
}
func legacyState() (active, masked bool) {
	a, _ := sh("systemctl", "is-active", legacyUnit)
	e, _ := sh("systemctl", "is-enabled", legacyUnit)
	return a == "active", e == "masked" || e == "masked-runtime"
}
func listeningDHCP() bool {
	out, _ := sh("ss", "-lunp")
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "ghostd") && strings.Contains(line, ":67 ") {
			return true
		}
	}
	return false
}
func bindingFor(address string) map[string]any {
	b, _ := registry()["bindings"].([]any)
	for _, x := range b {
		m := x.(map[string]any)
		if m["address"] == address && m["state"] == "active" {
			return m
		}
	}
	return nil
}

const firewallDoc = `{"zones":{"trusted":{"interfaces":["tailscale0"]},"lan":{"interfaces":["lab0"],"services":["dns","dhcp"],"ports":[{"port":%d,"proto":"tcp"}]}}}`

func target(enabled bool) string {
	return fmt.Sprintf(`{"scopes":[{"id":"lan","interface":"lab0","subnet":"10.77.0.0/24","server":"10.77.0.1","router":"10.77.0.1","start":"10.77.0.10","end":"10.77.0.30","zone":"lab.home.arpa","lease_seconds":600,"enabled":%t}],"devices":[]}`, enabled)
}
func beginReq(secs int) string {
	return fmt.Sprintf(`{"action":"begin","seconds":%d,"target":%s,"legacy":{"unit":%q,"config_path":"/etc/dnsmasq-ghostd-lab.conf","lease_path":"/var/lib/misc/e2e.leases"}}`, secs, target(true), legacyUnit)
}

func pre() {
	step("daemon boots under systemd with no policy and serves GetState")
	waitReady()
	st, err := rpc(func(ctx context.Context, c pb.HostStateClient) (*pb.State, error) {
		return c.GetState(ctx, &pb.GetStateRequest{IncludeAdoptionEvidence: true})
	})
	check(err == nil && strings.Contains(st.GetNftRulesetJson(), "nftables"), "GetState returns the live ruleset (%v)", err)
	check(err == nil && st.GetAdoptionEvidenceJson() != "", "adoption evidence captured")
	check(nft() == "", "no ghostd table before the first apply")

	step("firewall: apply, confirm from a fresh connection, table is live")
	lease, err := apply("firewall", fmt.Sprintf(firewallDoc, 8080), 60)
	must(err, "apply firewall")
	check(strings.Contains(nft(), "8080"), "table carries the applied port")
	must(confirm(lease), "confirm firewall")
	check(confirm(lease) != nil, "a second confirmation of the same lease is refused")

	step("firewall: unconfirmed apply is reverted by the independent systemd timer")
	lease, err = apply("firewall", fmt.Sprintf(firewallDoc, 9090), 6)
	must(err, "apply 9090")
	check(strings.Contains(nft(), "9090"), "9090 applied")
	timers, _ := sh("systemctl", "list-timers", "ghostd-revert-*", "--no-pager")
	check(strings.Contains(timers, "ghostd-revert-"), "a revert timer is armed")
	_, err = apply("firewall", fmt.Sprintf(firewallDoc, 7070), 60)
	check(err != nil, "a second apply is refused while a lease is pending")
	eventually("timer to restore the confirmed table", 30*time.Second, func() bool { return strings.Contains(nft(), "8080") && !strings.Contains(nft(), "9090") })
	check(confirm(lease) != nil, "confirming the reverted lease is refused")

	step("firewall: daemon killed with a change pending -> boot recovery rolls it back")
	lease, err = apply("firewall", fmt.Sprintf(firewallDoc, 9191), 300)
	must(err, "apply 9191")
	check(strings.Contains(nft(), "9191"), "9191 applied")
	restartGhostd(true)
	check(strings.Contains(nft(), "8080") && !strings.Contains(nft(), "9191"), "restart restored the confirmed table, dropping the pending one")
	check(confirm(lease) != nil, "the recovered lease cannot be confirmed")

	step("netconfig: sysctl action applied and confirmed")
	shOK("sysctl", "-w", "net.ipv4.ip_forward=0")
	lease, err = apply("netconfig", `{"actions":[["sysctl","net.ipv4.ip_forward=1"]]}`, 60)
	must(err, "apply netconfig")
	v, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	check(strings.TrimSpace(string(v)) == "1", "ip_forward is 1")
	must(confirm(lease), "confirm netconfig")

	step("legacy dnsmasq serves a client")
	shOK("systemctl", "start", legacyUnit)
	time.Sleep(time.Second)
	addr1 := dhcp("client1")
	check(strings.HasPrefix(addr1, "10.77.0."), "dnsmasq leased %s to client1", addr1)
	os.WriteFile("/var/lib/e2e.addr1", []byte(addr1), 0644)

	step("takeover: begin via RPC")
	j, err := handover(beginReq(120))
	must(err, "begin")
	check(phase() == "pending", "handover pending (%v)", j["Phase"])
	active, masked := legacyState()
	check(!active && masked, "dnsmasq stopped and persistently masked")
	check(soa("udp") && soa("tcp"), "authoritative SOA over UDP and TCP")
	check(dhcp("client1") == addr1, "client1 keeps %s (renewal served by ghostd)", addr1)
	b := bindingFor(addr1)
	check(b != nil, "registry holds the imported binding")
	addr2 := dhcp("client2")
	check(strings.HasPrefix(addr2, "10.77.0.") && addr2 != addr1, "client2 gets a fresh allocation %s", addr2)
	os.WriteFile("/var/lib/e2e.addr2", []byte(addr2), 0644)

	step("takeover: ghostd killed mid-window, restarted, still pending and serving")
	restartGhostd(true)
	check(phase() == "pending", "handover still pending after crash")
	check(dhcp("client1") == addr1, "renewal still served")
	_, err = apply("dhcp-v1", target(true), 60)
	check(err != nil, "ordinary DHCP apply refused during the takeover window")

	step("takeover: confirm")
	_, err = handover(`{"action":"confirm"}`)
	must(err, "confirm handover")
	check(phase() == "confirmed", "handover confirmed")
}

func post() {
	step("after reboot: daemon restores confirmed state before serving")
	waitReady()
	check(strings.Contains(nft(), "8080"), "confirmed firewall table restored at boot")
	v, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	check(strings.TrimSpace(string(v)) == "1", "confirmed netconfig sysctl replayed")
	check(phase() == "confirmed", "handover still confirmed")
	active, masked := legacyState()
	check(!active && masked, "dnsmasq still masked and not running (no second allocator after reboot)")
	check(soa("udp") && soa("tcp"), "authoritative DNS serving after reboot")
	addr1, _ := os.ReadFile("/var/lib/e2e.addr1")
	addr2, _ := os.ReadFile("/var/lib/e2e.addr2")
	check(dhcp("client1") == strings.TrimSpace(string(addr1)), "client1 renews its address from ghostd")
	check(dhcp("client2") == strings.TrimSpace(string(addr2)), "client2 renews its address from ghostd")

	step("rollback: dnsmasq resumes with every lease, including ghostd's new grant")
	_, err := handover(`{"action":"rollback"}`)
	must(err, "rollback")
	active, masked = legacyState()
	check(active && !masked, "dnsmasq active and unmasked")
	check(phase() == "rolled-back", "journal says rolled-back")
	leases, _ := os.ReadFile("/var/lib/misc/e2e.leases")
	check(strings.Contains(string(leases), strings.TrimSpace(string(addr1))) && strings.Contains(string(leases), strings.TrimSpace(string(addr2))), "lease file carries both addresses:\n%s", leases)
	check(dhcp("client2") == strings.TrimSpace(string(addr2)), "client2 keeps its address under dnsmasq")
}

func expiry() {
	waitReady()
	step("expiry: an unconfirmed takeover rolls back on its own")
	_, err := handover(beginReq(30))
	must(err, "begin")
	check(phase() == "pending", "pending")
	eventually("watcher rollback at the deadline", 90*time.Second, func() bool { return phase() == "rolled-back" })
	active, masked := legacyState()
	check(active && !masked, "dnsmasq restored")

	step("expiry: daemon down through the deadline -> boot recovery rolls back before serving")
	_, err = handover(beginReq(30))
	must(err, "begin")
	shOK("systemctl", "stop", "ghostd.service")
	time.Sleep(35 * time.Second)
	shOK("systemctl", "start", "ghostd.service")
	waitReady()
	check(phase() == "rolled-back", "boot recovery rolled the expired takeover back (%s)", phase())
	active, masked = legacyState()
	check(active && !masked, "dnsmasq restored by boot recovery")
	check(!listeningDHCP(), "ghostd is not serving DHCP alongside dnsmasq")
	addr2, _ := os.ReadFile("/var/lib/e2e.addr2")
	check(dhcp("client2") == strings.TrimSpace(string(addr2)), "no lease lost across two takeovers")
}

func main() {
	_ = net.IPv4len
	if len(os.Args) < 2 {
		fmt.Println("usage: probe pre|post|expiry")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "pre":
		pre()
	case "post":
		post()
	case "expiry":
		expiry()
	default:
		os.Exit(2)
	}
	if failures > 0 {
		fmt.Printf("\n%d check(s) failed\n", failures)
		os.Exit(1)
	}
	fmt.Println("\nall checks passed")
}
