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

// tftpGet fetches a file from the LAN's TFTP server as a client in a namespace.
func tftpGet(ns, name string) ([]byte, error) {
	dl := "/tmp/" + ns + ".tftp"
	os.Remove(dl)
	out, err := sh("nsenter", "--net=/run/netns/"+ns, "--", "busybox", "tftp", "-g", "-r", name, "-l", dl, "10.77.0.1")
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, out)
	}
	return os.ReadFile(dl)
}
func sameAsBootFile(got []byte) bool {
	want, _ := os.ReadFile("/srv/tftp/pxe.bin")
	return len(want) > 0 && string(got) == string(want)
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

const firewallDoc = `{"zones":{"trusted":{"interfaces":["tailscale0"]},"ctr":{"interfaces":["ctr0","ctr1"],"services":["mdns"]},"lan":{"interfaces":["lab0"],"services":["dns","dhcp","mdns","tftp"],"ports":[{"port":%d,"proto":"tcp"}]}}}`

func target(enabled bool) string {
	return fmt.Sprintf(`{"scopes":[{"id":"lan","interface":"lab0","subnet":"10.77.0.0/24","server":"10.77.0.1","router":"10.77.0.1","start":"10.77.0.10","end":"10.77.0.30","zone":"lab.home.arpa","lease_seconds":600,"enabled":%t}],"devices":[]}`, enabled)
}

// beginReq builds the handover request from the converter's own preview of the
// legacy dnsmasq configuration, so the plan an operator would review is the plan
// the lab takes over with.
func beginReq(secs int, evidence bool) string {
	raw, err := exec.Command("/opt/ghostd/ghostd", "--convert-dnsmasq=/etc/dnsmasq-ghostd-lab.conf", "--legacy-unit="+legacyUnit).Output() // stdout only: logs go to stderr
	must(err, "ghostd --convert-dnsmasq")
	out := string(raw)
	var plan struct {
		Target json.RawMessage `json:"target"`
		Legacy json.RawMessage `json:"legacy"`
	}
	must(json.Unmarshal([]byte(out), &plan), "plan json")
	return fmt.Sprintf(`{"action":"begin","seconds":%d,"require_evidence":%t,"target":%s,"legacy":%s}`, secs, evidence, plan.Target, plan.Legacy)
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

	step("PXE: legacy dnsmasq hands out the boot file and serves it over TFTP")
	got, err := tftpGet("client1", "pxe.bin")
	check(err == nil && sameAsBootFile(got), "dnsmasq serves pxe.bin over TFTP (%v)", err)

	step("takeover: the converter previews the legacy config as a plan")
	prev, err := sh("/opt/ghostd/ghostd", "--convert-dnsmasq=/etc/dnsmasq-ghostd-lab.conf", "--legacy-unit="+legacyUnit)
	check(err == nil && strings.Contains(prev, `"server": "10.77.0.1"`) && strings.Contains(prev, `"lease_seconds": 600`), "plan carries the scope, server and lifetime: %v", err)
	check(func() bool { _, e := sh("/opt/ghostd/ghostd", "--convert-dnsmasq=/etc/hostname"); return e != nil }(), "a non-dnsmasq file is refused")

	step("takeover: begin via RPC")
	j, err := handover(beginReq(120, true))
	must(err, "begin")
	check(phase() == "pending", "handover pending (%v)", j["Phase"])
	active, masked := legacyState()
	check(!active && masked, "dnsmasq stopped and persistently masked")
	check(soa("udp") && soa("tcp"), "authoritative SOA over UDP and TCP")
	hs, _ := handover(`{"action":"status"}`)
	miss, _ := hs["pending_verification"].([]any)
	check(len(miss) == 2 && hs["remaining_seconds"] != nil, "status lists what still needs client verification: %v", miss)
	_, err = handover(`{"action":"confirm"}`)
	check(err != nil && strings.Contains(err.Error(), "client verification incomplete"), "confirmation refused before any client has been seen (%v)", err)
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

	step("PXE: after the takeover ghostd serves the same boot file, and only that tree")
	// Like dnsmasq, ghostd hands the boot fields only to clients that ask: ISC
	// dhclient's default request list does not, so its lease carries none.
	lease1, _ := os.ReadFile("/tmp/client1.leases")
	check(!strings.Contains(string(lease1[max(0, len(lease1)-900):]), `filename "pxe.bin"`), "a client that did not ask for boot options is not handed any (as dnsmasq)")
	got, err = tftpGet("client1", "pxe.bin")
	check(err == nil && sameAsBootFile(got), "ghostd serves pxe.bin over TFTP behind the firewall's conntrack helper (%v)", err)
	for _, bad := range []string{"../../etc/e2e-secret", "/etc/e2e-secret", "../e2e-secret"} {
		_, err = tftpGet("client1", bad)
		check(err != nil, "%s is refused", bad)
	}

	step("takeover: confirm once real clients have renewed and been allocated")
	hs, _ = handover(`{"action":"status"}`)
	miss, _ = hs["pending_verification"].([]any)
	check(len(miss) == 0, "no verification outstanding: %v", hs["evidence"])
	_, err = handover(`{"action":"confirm"}`)
	must(err, "confirm handover")
	check(phase() == "confirmed", "handover confirmed")
	hist, err := rpc(func(ctx context.Context, c pb.HostStateClient) (*pb.RegistryResponse, error) {
		return c.DHCPHandover(ctx, &pb.RegistryDocument{Json: `{"action":"history"}`})
	})
	check(err == nil && strings.Contains(hist.GetJson(), `"confirmed"`), "confirmed takeover is archived in history")
}

func ask(server, name string, typ uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, typ)
	r, _, err := (&dns.Client{Net: "udp", Timeout: 5 * time.Second}).Exchange(q, server+":53")
	if err != nil {
		return nil
	}
	return r
}

// dnsPhase covers .local without avahi on the host (a third-party responder in
// its own namespace stands in for a LAN printer) and the per-container ACL.
func dnsPhase() {
	waitReady()
	step("mDNS: .local resolves through ghostd's native client, with no avahi on the host")
	avahi, _ := sh("systemctl", "is-active", "avahi-daemon.service")
	check(avahi != "active", "the host's own avahi is not running (%s)", avahi)
	var r *dns.Msg
	eventually("printer.local to resolve", 20*time.Second, func() bool {
		r = ask("100.64.0.1", "printer.local.", dns.TypeA)
		return r != nil && len(r.Answer) == 1
	})
	if r != nil && len(r.Answer) == 1 {
		check(r.Answer[0].(*dns.A).A.String() == "10.77.0.60", "printer.local -> %s", r.Answer[0].(*dns.A).A)
	}

	step("ACL: identities see only their own service classes, on their own listeners")
	const printing, music = "100.64.0.21", "100.64.0.22"
	r = ask(printing, "printer.local.", dns.TypeA)
	check(r != nil && r.Rcode == dns.RcodeRefused, "printer.local is refused for printing until a permitted browse offers it")
	r = ask(music, "printer.local.", dns.TypeA)
	check(r != nil && r.Rcode == dns.RcodeRefused, "and for music")
	r = ask(printing, "_ipp._tcp.local.", dns.TypePTR)
	check(r != nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) >= 1, "printing can browse _ipp._tcp")
	r = ask(printing, "_googlecast._tcp.local.", dns.TypePTR)
	check(r != nil && r.Rcode == dns.RcodeRefused, "printing cannot browse _googlecast._tcp")
	r = ask(music, "_ipp._tcp.local.", dns.TypePTR)
	check(r != nil && r.Rcode == dns.RcodeRefused, "music cannot browse _ipp._tcp")
	if r = ask(printing, "_ipp._tcp.local.", dns.TypePTR); r != nil && len(r.Answer) > 0 {
		target := r.Answer[0].(*dns.PTR).Ptr
		s := ask(printing, target, dns.TypeSRV)
		check(s != nil && len(s.Answer) == 1, "instance %s has an SRV record", target)
	}
	a := ask(printing, "printer.local.", dns.TypeA)
	check(a != nil && len(a.Answer) == 1, "printer.local resolvable for printing once its browse named it")
	a = ask(music, "printer.local.", dns.TypeA)
	check(a != nil && a.Rcode == dns.RcodeRefused, "printing's grant does not leak to music")
	r = ask(music, "_googlecast._tcp.local.", dns.TypePTR)
	check(r != nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) >= 1, "music can browse _googlecast._tcp")
	r = ask(printing, "example.com.", dns.TypeA)
	check(r != nil && r.Rcode == dns.RcodeRefused, "an unlisted ordinary name is refused before any cache or upstream")
	r = ask("100.64.0.1", "_googlecast._tcp.local.", dns.TypePTR)
	check(r != nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) >= 1, "the base listener stays unrestricted")
	mdnsPhase()
}

const mdnsAdvert = `{"interfaces":["lab0"],"host":"nas","reflect":[{"lan":"lab0","network":"ctr0","allow_services":["_ipp._tcp"]},{"lan":"lab0","network":"ctr1","allow_services":["_googlecast._tcp"]}],"records":[{"service":"_smb._tcp","instance":"NAS Share","port":445},{"service":"_ipp._tcp","instance":"Shared Queue","port":631,"txt":["rp=ipp/print"],"subtypes":["_universal"]}]}`

// zc asks the LAN's multicast DNS as another host would: python-zeroconf, an
// independent implementation, inside the printer's namespace.
func zc(args ...string) string { return zcIn("printer", "10.77.0.60", args...) }

// zcIn runs the client inside a namespace, bound to that namespace's address.
func zcIn(ns, addr string, args ...string) string {
	cmd := exec.Command("nsenter", append([]string{"--net=/run/netns/" + ns, "--", "env", "ZC_IFACE=" + addr, "python3", "/opt/ghostd/zc.py"}, args...)...)
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(string(out))
}

func mdnsPhase() {
	const smb, smbName = "_smb._tcp.local.", "NAS Share._smb._tcp.local."
	step("mDNS advertisement: ghostd answers for the declared record set (no other responder on the host)")
	lease, err := apply("mdns-v1", mdnsAdvert, 60)
	must(err, "apply mdns-v1")
	must(confirm(lease), "confirm mdns-v1")
	var info string
	eventually("a third-party client to resolve the SMB instance", 30*time.Second, func() bool {
		info = zc("info", smb, smbName)
		return strings.Contains(info, "port=445")
	})
	check(strings.Contains(info, "addrs=10.77.0.1") && strings.Contains(info, "server=nas.local."), "SRV/A carry the port, host and address: %s", info)
	check(strings.Contains(zc("browse", smb), "NAS Share"), "browse finds the SMB instance")
	txtOK := eventually("TXT records to be served", 20*time.Second, func() bool {
		return strings.Contains(zc("info", "_ipp._tcp.local.", "Shared Queue._ipp._tcp.local."), "txt=rp=ipp/print")
	})
	check(txtOK, "TXT records are served")
	check(strings.Contains(zc("browse", "_universal._sub._ipp._tcp.local."), "Shared Queue"), "subtype browse works")
	check(!strings.Contains(zc("browse", "_googlecast._tcp.local."), "NAS"), "ghostd is silent about services it does not advertise")
	r := ask("100.64.0.1", "nas.local.", dns.TypeA)
	check(r != nil && len(r.Answer) == 1, "ghostd's own resolver finds nas.local through the LAN")

	step("mDNS reflector: each container network sees only its own service classes from the LAN")
	// ctr0 may browse printers: the avahi printer on the LAN appears in its multicast domain.
	var seen string
	eventually("the LAN printer to be reflected into ctr0", 30*time.Second, func() bool {
		seen = zcIn("cnt0", "10.90.0.10", "browse", "_ipp._tcp.local.")
		return strings.Contains(seen, "Lobby Printer")
	})
	check(!strings.Contains(seen, "Shared Queue"), "ghostd's own advertisement is not reflected back at a container: %q", seen)
	cinfo := zcIn("cnt0", "10.90.0.10", "info", "_ipp._tcp.local.", "Lobby Printer._ipp._tcp.local.")
	check(strings.Contains(cinfo, "port=631") && strings.Contains(cinfo, "10.77.0.60") && strings.Contains(cinfo, "server=printer.local."), "the instance's SRV, TXT and address came through: %s", cinfo)
	check(zcIn("cnt0", "10.90.0.10", "browse", "_googlecast._tcp.local.") == "", "ctr0 cannot see the speaker")
	check(zcIn("cnt0", "10.90.0.10", "info", "_googlecast._tcp.local.", "Lobby Speaker._googlecast._tcp.local.") == "none", "nor resolve it directly")
	check(strings.Contains(zcIn("cnt1", "10.91.0.10", "browse", "_googlecast._tcp.local."), "Lobby Speaker"), "ctr1 sees the speaker")
	check(zcIn("cnt1", "10.91.0.10", "browse", "_ipp._tcp.local.") == "", "and not the printer")
	check(zcIn("cnt1", "10.91.0.10", "info", "_ipp._tcp.local.", "Lobby Printer._ipp._tcp.local.") == "none", "not even by name")

	step("mDNS advertisement: a name another host already owns is refused, and the old set keeps answering")
	clash := `{"interfaces":["lab0"],"host":"nas","records":[{"service":"_ipp._tcp","instance":"Lobby Printer","port":631}]}`
	_, err = apply("mdns-v1", clash, 6)
	check(err != nil && strings.Contains(err.Error(), "already advertised"), "advertising over avahi's Lobby Printer is refused (%v)", err)
	// The failed apply left its lease armed; let it revert on its own, which
	// also proves the rollback path re-establishes the previous record set.
	eventually("the failed change to revert to the confirmed set", 60*time.Second, func() bool {
		return strings.Contains(zc("info", smb, smbName), "port=445")
	})

	step("mDNS advertisement: an unconfirmed change reverts by itself")
	eventually("the failed change's lease to lapse", 40*time.Second, func() bool { _, e := apply("mdns-v1", `{}`, 8); return e == nil })
	check(strings.Contains(zc("info", smb, smbName), "none"), "withdrawn immediately (goodbye)")
	eventually("timer revert to bring the advertisement back", 60*time.Second, func() bool { return strings.Contains(zc("info", smb, smbName), "port=445") })
	l2, err := apply("mdns-v1", mdnsAdvert, 60)
	must(err, "reapply")
	must(confirm(l2), "confirm reapply")
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

	step("peer inventory: a direct tailnet endpoint at a leased address becomes a reviewable suggestion")
	a1 := strings.TrimSpace(string(addr1))
	peers := fmt.Sprintf(`{"nodekey:%s":{"ID":"n-client1","HostName":"nas","DNSName":"nas.e2e.ts.net.","TailscaleIPs":["100.64.0.9"],"CurAddr":"%s:41641","Addrs":["203.0.113.7:41641"],"Online":true}}`, strings.Repeat("ab", 32), a1)
	must(os.WriteFile("/run/tailscale/peers.json", []byte(peers), 0644), "write peers")
	var sugg []map[string]any
	eventually("the watcher to poll peers and produce a suggestion", 90*time.Second, func() bool {
		r, err := rpc(func(ctx context.Context, c pb.HostStateClient) (*pb.RegistryResponse, error) {
			return c.GetSuggestions(ctx, &pb.RegistryRequest{})
		})
		return err == nil && json.Unmarshal([]byte(r.Json), &sugg) == nil && len(sugg) > 0
	})
	if len(sugg) > 0 {
		check(sugg[0]["strength"] == "endpoint" && sugg[0]["address"] == a1 && sugg[0]["peer_id"] == "n-client1", "endpoint-strength suggestion for %s: %v", a1, sugg[0]["evidence"])
		check(bindingFor(a1)["tailnet_node_id"] == nil, "nothing was applied by itself")
		repair, _ := json.Marshal([]any{sugg[0]["repair"]})
		_, err := rpc(func(ctx context.Context, c pb.HostStateClient) (*pb.RegistryResponse, error) {
			return c.RepairIdentity(ctx, &pb.RegistryDocument{Json: string(repair)})
		})
		check(err == nil, "reviewer applies the suggestion through RepairIdentity (%v)", err)
		check(bindingFor(a1)["tailnet_node_id"] == "n-client1", "binding now linked to the tailnet node")
		check(dhcp("client1") == a1 && bindingFor(a1)["tailnet_node_id"] == "n-client1", "association survives the client's next renewal")
	}

	step("switch evidence: imported as an observation, never a grant")
	_, err := rpc(func(ctx context.Context, c pb.HostStateClient) (*pb.RegistryResponse, error) {
		return c.ImportObservations(ctx, &pb.RegistryDocument{Json: `{"ttl_seconds":600,"observations":[{"scope":"lab0","address":"10.77.0.99","mac":"02:00:00:00:00:99","detail":"sw1 Gi1/0/7"}]}`})
	})
	check(err == nil, "ImportObservations accepted (%v)", err)
	obs, _ := registry()["observations"].([]any)
	found := false
	for _, o := range obs {
		m := o.(map[string]any)
		found = found || (m["origin"] == "switch-snooping" && m["address"] == "10.77.0.99")
	}
	check(found && bindingFor("10.77.0.99") == nil, "switch sighting recorded without a binding")

	step("mDNS advertisement survives the reboot")
	eventually("confirmed advertisement to be answering again", 40*time.Second, func() bool {
		return strings.Contains(zc("info", "_smb._tcp.local.", "NAS Share._smb._tcp.local."), "port=445")
	})

	step("rollback: dnsmasq resumes with every lease, including ghostd's new grant")
	_, err = handover(`{"action":"rollback"}`)
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
	_, err := handover(beginReq(30, false))
	must(err, "begin")
	check(phase() == "pending", "pending")
	eventually("watcher rollback at the deadline", 90*time.Second, func() bool { return phase() == "rolled-back" })
	active, masked := legacyState()
	check(active && !masked, "dnsmasq restored")

	step("expiry: daemon down through the deadline -> boot recovery rolls back before serving")
	_, err = handover(beginReq(30, false))
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

// minimalPhase checks a daemon built with no optional features: the core works,
// and nothing else is present — not the code, not the domains, not the sockets.
func minimalPhase() {
	waitReady()
	step("minimal build: no optional feature is compiled in")
	out, err := sh("/opt/ghostd/ghostd", "--features")
	check(err == nil && strings.Contains(out, "optional: none"), "--features reports none: %q", out)
	step("minimal build: the core domains still work end to end")
	lease, err := apply("firewall", fmt.Sprintf(firewallDoc, 8080), 60)
	must(err, "apply firewall")
	check(strings.Contains(nft(), "8080"), "firewall applied")
	must(confirm(lease), "confirm firewall")
	lease, err = apply("netconfig", `{"actions":[["sysctl","net.ipv4.ip_forward=1"]]}`, 60)
	must(err, "apply netconfig")
	must(confirm(lease), "confirm netconfig")
	step("minimal build: optional domains and RPCs are refused, not half-present")
	for _, domain := range []string{"dhcp-v1", "mdns-v1"} {
		_, err = apply(domain, `{}`, 30)
		check(err != nil && strings.Contains(err.Error(), "must be one of"), "%s is not an available domain (%v)", domain, err)
	}
	_, err = rpc(func(ctx context.Context, c pb.HostStateClient) (*pb.RegistryResponse, error) {
		return c.GetRegistry(ctx, &pb.RegistryRequest{})
	})
	check(err != nil && strings.Contains(err.Error(), "Unimplemented"), "GetRegistry is unimplemented (%v)", err)
	_, err = rpc(func(ctx context.Context, c pb.HostStateClient) (*pb.RegistryResponse, error) {
		return c.DHCPHandover(ctx, &pb.RegistryDocument{Json: `{"action":"status"}`})
	})
	check(err != nil && strings.Contains(err.Error(), "Unimplemented"), "DHCPHandover is unimplemented (%v)", err)
	step("minimal build: no DNS, DHCP or mDNS socket is open")
	sockets, _ := sh("ss", "-lunpH")
	for _, port := range []string{":53 ", ":67 ", ":547 ", ":5353 ", ":69 "} {
		owned := false
		for _, line := range strings.Split(sockets, "\n") {
			if strings.Contains(line, "ghostd") && strings.Contains(line, port) {
				owned = true
			}
		}
		check(!owned, "ghostd holds no UDP %s", strings.TrimSpace(port))
	}
	tcp, _ := sh("ss", "-ltnpH")
	check(!strings.Contains(tcp, ":53 "), "ghostd holds no TCP 53")
	if _, err := os.Stat("/run/ghostd/dns.env"); err == nil {
		check(false, "the container resolver published dns.env")
	} else {
		check(true, "no container resolver environment published")
	}
}

// headscalePhase: the caller holds a deploy capability and no tag. Headscale has
// no capability grants, so the provider must not believe one; authorization is by
// tag or a listed login (--deployer-user).
func headscalePhase() {
	waitReady()
	step("headscale provider: the daemon runs with the headscale overlay")
	out, _ := sh("/opt/ghostd/ghostd", "--features")
	check(strings.Contains(out, "overlay: headscale"), "only the headscale provider is built in: %q", out)
	logs, _ := sh("journalctl", "-u", "ghostd.service", "-n", "50", "--no-pager")
	check(strings.Contains(logs, "headscale overlay only"), "the listener reports the headscale overlay")
	step("headscale provider: reads work, a claimed capability does not authorize")
	_, err := rpc(func(ctx context.Context, c pb.HostStateClient) (*pb.State, error) {
		return c.GetState(ctx, &pb.GetStateRequest{})
	})
	check(err == nil, "any overlay node may read state (%v)", err)
	_, err = apply("firewall", fmt.Sprintf(firewallDoc, 8080), 60)
	check(err != nil && strings.Contains(err.Error(), "PermissionDenied"), "deploy capability alone is refused: %v", err)
	step("headscale provider: a listed login is authorized")
	shOK("sed", "-i", "s#--overlay=headscale#--overlay=headscale --deployer-user=operator@example.com#", "/etc/systemd/system/ghostd.service")
	shOK("systemctl", "daemon-reload")
	shOK("systemctl", "restart", "ghostd.service")
	waitReady()
	lease, err := apply("firewall", fmt.Sprintf(firewallDoc, 8080), 60)
	check(err == nil, "the listed login can deploy (%v)", err)
	if err == nil {
		check(confirm(lease) == nil, "and confirm")
	}
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
	case "dns":
		dnsPhase()
	case "minimal":
		minimalPhase()
	case "headscale":
		headscalePhase()
	case "apply": // debugging aid: probe apply <domain> <seconds> <file>
		raw, err := os.ReadFile(os.Args[4])
		must(err, "read target")
		secs := 0
		fmt.Sscan(os.Args[3], &secs)
		lease, err := apply(os.Args[2], string(raw), int32(secs))
		fmt.Println("lease:", lease, "err:", err)
		return
	default:
		os.Exit(2)
	}
	if failures > 0 {
		fmt.Printf("\n%d check(s) failed\n", failures)
		os.Exit(1)
	}
	fmt.Println("\nall checks passed")
}
