//go:build dnsmasq && dhcp && linux

package addressbook

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/xaiki/ghostd/internal/wellknown"
)

type labDNSmasq struct {
	cmd          *exec.Cmd
	config, path string
	log          *os.File
}

func (l *labDNSmasq) Start() error {
	if l.cmd != nil {
		return nil
	}
	l.cmd = exec.Command("dnsmasq", "--no-daemon", "--conf-file="+l.config)
	l.cmd.Stdout = l.log
	l.cmd.Stderr = l.log
	if e := l.cmd.Start(); e != nil {
		l.cmd = nil
		return e
	}
	time.Sleep(300 * time.Millisecond)
	return nil
}
func (l *labDNSmasq) Stop() error {
	if l.cmd == nil {
		return nil
	}
	_ = l.cmd.Process.Signal(os.Interrupt)
	_ = l.cmd.Wait()
	l.cmd = nil
	return nil
}
func (l *labDNSmasq) ReadLeases() (string, error) { b, e := os.ReadFile(l.path); return string(b), e }
func (l *labDNSmasq) WriteLeases(s string) error  { return os.WriteFile(l.path, []byte(s), 0600) }
func (l *labDNSmasq) Validate(c Config) error {
	b, e := os.ReadFile(l.config)
	if e != nil {
		return e
	}
	return ValidateDNSmasqConfig(c, string(b), l.path)
}

// Run only in the disposable --network none lab container. This test creates
// real network namespaces and uses ISC dhclient against dnsmasq and CoreDHCP.
func TestDNSmasqTakeoverLab(t *testing.T) {
	if os.Getenv("GHOSTD_DHCP_LAB") != "1" {
		t.Skip("isolated privileged container required")
	}
	dir := t.TempDir()
	command := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		if len(args) > 3 && args[0] == "ip" && args[1] == "netns" && args[2] == "exec" {
			args = append([]string{"nsenter", "--net=/run/netns/" + args[3], "--"}, args[4:]...)
		}
		b, e := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if e != nil {
			t.Fatalf("%v: %v\n%s", args, e, b)
		}
		return string(b)
	}
	if e := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0644); e != nil {
		t.Fatal(e)
	}
	if os.Getenv("GHOSTD_LAB_SYSTEMD") == "1" {
		command("systemctl", "stop", "dnsmasq.service")
	}
	command("ip", "link", "add", "lab0", "type", "bridge")
	t.Cleanup(func() { exec.Command("ip", "link", "del", "lab0").Run() })
	command("ip", "addr", "add", "10.77.0.1/24", "dev", "lab0")
	command("ip", "-6", "addr", "add", "fd77::1/64", "dev", "lab0", "nodad")
	command("ip", "link", "set", "lab0", "up")
	for _, name := range []string{"client1", "client2"} {
		command("ip", "netns", "add", name)
		t.Cleanup(func() {
			raw, _ := exec.Command("ip", "netns", "pids", name).Output()
			for _, pid := range strings.Fields(string(raw)) {
				exec.Command("kill", "-KILL", pid).Run()
			}
			exec.Command("ip", "netns", "del", name).Run()
		})
		command("ip", "link", "add", name, "type", "veth", "peer", "name", name+"p")
		command("ip", "link", "set", name, "master", "lab0")
		command("ip", "link", "set", name, "up")
		command("ip", "link", "set", name+"p", "netns", name)
		command("ip", "netns", "exec", name, "ip", "link", "set", "lo", "up")
		command("ip", "netns", "exec", name, "ip", "link", "set", name+"p", "up")
	}
	time.Sleep(2 * time.Second)
	path := filepath.Join(dir, "dnsmasq.leases")
	os.WriteFile(path, nil, 0600)
	conf := filepath.Join(dir, "dnsmasq.conf")
	text := "interface=lab0\nbind-interfaces\nno-resolv\nno-hosts\nuser=root\ndomain=lab.home.arpa\ndhcp-leasefile=" + path + "\ndhcp-range=10.77.0.10,10.77.0.30,255.255.255.0,10m\ndhcp-range=fd77::10,fd77::30,64,10m\nenable-ra\n"
	os.WriteFile(conf, []byte(text), 0600)
	log, _ := os.Create(filepath.Join(dir, "dnsmasq.log"))
	defer log.Close()
	var legacy LegacyAuthority = &labDNSmasq{config: conf, path: path, log: log}
	legacySpec := LegacySpec{}
	if os.Getenv("GHOSTD_LAB_SYSTEMD") == "1" {
		legacySpec = LegacySpec{Unit: "dnsmasq@ghostd-lab.service", ConfigPath: conf, LeasePath: path}
		unit := "[Unit]\nDescription=Isolated dnsmasq migration fixture\n[Service]\nExecStart=/usr/sbin/dnsmasq --no-daemon --conf-file=" + conf + "\n"
		if e := os.WriteFile("/run/systemd/system/"+legacySpec.Unit, []byte(unit), 0644); e != nil {
			t.Fatal(e)
		}
		command("systemctl", "daemon-reload")
		legacy = SystemDNSmasq{Spec: legacySpec}
	}
	t.Cleanup(func() { legacy.Stop(); b, _ := os.ReadFile(log.Name()); t.Log(string(b)) })
	if e := legacy.Start(); e != nil {
		t.Fatal(e)
	}
	client := func(name string, family int) {
		t.Helper()
		pid := filepath.Join(dir, fmt.Sprintf("%s-%d.pid", name, family))
		lease := filepath.Join(dir, fmt.Sprintf("%s-%d.leases", name, family))
		// Stop only this test client's daemon; preserve its lease to exercise INIT-REBOOT.
		if raw, e := os.ReadFile(pid); e == nil {
			exec.Command("kill", strings.TrimSpace(string(raw))).Run()
			time.Sleep(200 * time.Millisecond)
		}
		out := command("ip", "netns", "exec", name, "dhclient", fmt.Sprintf("-%d", family), "-1", "-v", "-lf", lease, "-pf", pid, name+"p")
		t.Log(out)
	}
	client("client1", 4)
	client("client1", 6)
	original, e := legacy.ReadLeases()
	if e != nil {
		t.Fatal(e)
	}
	t.Log("legacy leases", original)
	cfg := Config{Scopes: []Scope{
		{ID: "lan4", Interface: "lab0", Subnet: "10.77.0.0/24", Server: "10.77.0.1", Router: "10.77.0.1", Start: "10.77.0.10", End: "10.77.0.30", Zone: "lab.home.arpa", LeaseSeconds: 600, Enabled: true},
		{ID: "lan6", Interface: "lab0", Subnet: "fd77::/64", Server: "fd77::1", Start: "fd77::10", End: "fd77::30", Zone: "lab.home.arpa", LeaseSeconds: 600, PreferredSeconds: 300, Enabled: true, RA: &RAConfig{Interval: 4, RouterLifetime: 1800}},
	}}
	store, e := Open(filepath.Join(dir, "registry.db"))
	if e != nil {
		t.Fatal(e)
	}
	manager := NewManager(store)
	t.Cleanup(func() { manager.Close(); store.Close() })
	var saved Config
	handover := Handover{Manager: manager, Legacy: legacy, SaveConfig: func(c Config) error { saved = c; return nil }}
	if e = handover.Begin(cfg, legacySpec, time.Minute*10); e != nil {
		t.Fatal(e)
	}
	if legacySpec.Unit != "" {
		output := command("systemctl", "show", legacySpec.Unit, "--property=UnitFileState", "--value")
		if strings.TrimSpace(output) != "masked" {
			t.Fatalf("legacy not persistently masked: %s", output)
		}
	}
	imported, e := store.Snapshot("", "", 0)
	if e != nil {
		t.Fatal(e)
	}
	if len(imported.Bindings) != 2 || imported.ServerDUID == "" {
		t.Fatalf("missing imports: %+v", imported)
	}
	client("client1", 4)
	client("client1", 6)
	client("client2", 4)
	client("client2", 6)
	t.Log(command("ip", "netns", "exec", "client2", "rdisc6", "-1", "client2p"))
	snapshot, e := store.Snapshot("", "", 0)
	if e != nil {
		t.Fatal(e)
	}
	if len(snapshot.Bindings) != 4 {
		raw, _ := json.Marshal(snapshot)
		t.Fatalf("expected four unique grants: %s", raw)
	}
	for _, b := range snapshot.Bindings {
		kind := uint16(dns.TypeA)
		if strings.Contains(b.Address, ":") {
			kind = dns.TypeAAAA
		}
		query := new(dns.Msg)
		query.SetQuestion(b.Name+".lab.home.arpa.", kind)
		for _, network := range []string{"udp", "tcp"} {
			reply, _, e := (&dns.Client{Net: network, Timeout: 2 * time.Second}).Exchange(query, "10.77.0.1:53")
			if e != nil || len(reply.Answer) == 0 {
				t.Fatalf("DNS %s: %v %v", network, reply, e)
			}
		}
	}
	if e = handover.Confirm(); e != nil {
		t.Fatal(e)
	}
	// Restart the new authority using the same durable ledger and configuration.
	manager.Close()
	store.Close()
	store, e = Open(filepath.Join(dir, "registry.db"))
	if e != nil {
		t.Fatal(e)
	}
	manager = NewManager(store)
	handover.Manager = manager
	if e = manager.Apply(saved, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	client("client2", 4)
	client("client2", 6)

	// Leave an unrequested OFFER outstanding and a DECLINEd address in
	// quarantine, then roll back: both must stay occupied for the real dnsmasq.
	probe := func(mode, mac string) string {
		t.Helper()
		// dhclient's fallback socket holds UDP 68 in the namespace; stop client2's.
		for _, family := range []int{4, 6} {
			if raw, e := os.ReadFile(filepath.Join(dir, fmt.Sprintf("client2-%d.pid", family))); e == nil {
				exec.Command("kill", strings.TrimSpace(string(raw))).Run()
			}
		}
		time.Sleep(300 * time.Millisecond)
		out := command("ip", "netns", "exec", "client2", "env", "GHOSTD_PROBE="+mode, "GHOSTD_PROBE_MAC="+mac, "GHOSTD_PROBE_IFACE=client2p", "/lab/test", "-test.run", "^TestDHCPProbeClient$", "-test.v")
		var ip string
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "PROBE ip=") {
				ip = strings.TrimPrefix(line, "PROBE ip=")
			}
		}
		if ip == "" {
			t.Fatalf("probe %s produced no address: %s", mode, out)
		}
		return ip
	}
	const declinerMAC, offereeMAC, strangerMAC = "00:aa:00:00:00:02", "00:aa:00:00:00:01", "00:aa:00:00:00:03"
	offered := probe("discover", offereeMAC)
	declined := probe("decline", declinerMAC)
	states := map[string]string{}
	mid, _ := store.Snapshot("lan4", "", 0)
	for _, b := range mid.Bindings {
		states[b.Address] = b.State
	}
	if states[offered] != "offered" || states[declined] != "declined" {
		t.Fatalf("expected offered %s and declined %s, got %v", offered, declined, states)
	}
	if e = handover.Rollback(); e != nil {
		t.Fatal(e)
	}
	exported, e := legacy.ReadLeases()
	if e != nil {
		t.Fatal(e)
	}
	doc, e := ParseDNSmasq(cfg, exported)
	if e != nil || len(doc.Leases) != 6 || doc.ServerDUID != snapshot.ServerDUID {
		t.Fatalf("rollback lost leases: %v %s", e, exported)
	}
	for _, l := range doc.Leases {
		if l.Address == declined && l.MAC == declinerMAC {
			t.Fatalf("declined address was exported under the decliner's own identity: %+v", l)
		}
	}
	// Real dnsmasq now serves: neither the decliner nor a stranger may be offered
	// an address that is still occupied.
	for _, mac := range []string{declinerMAC, strangerMAC} {
		got := probe("discover", mac)
		if got == declined || got == offered {
			t.Fatalf("dnsmasq offered occupied address %s to %s (offered=%s declined=%s)", got, mac, offered, declined)
		}
	}
	client("client1", 4)
	client("client1", 6)
	client("client2", 4)
	client("client2", 6)
	if _, e = net.ListenPacket("udp", wellknown.HostPort("0.0.0.0", wellknown.PortDHCPv4Server)); e == nil {
		t.Fatal("legacy authority no longer owns DHCP port")
	}
	// A failed configuration commit must restore the real old authority, keeping
	// all post-cutover grants. Then exercise deadline-driven recovery as well.
	saves := 0
	handover.SaveConfig = func(c Config) error {
		saves++
		if saves == 1 {
			return fmt.Errorf("injected commit failure")
		}
		saved = c
		return nil
	}
	if e = handover.Begin(cfg, legacySpec, time.Minute); e == nil {
		t.Fatal("injected failure was ignored")
	}
	if j, _ := store.HandoverJournal(); j.Phase != "rolled-back" {
		t.Fatalf("failure recovery incomplete: %+v; %v", j, e)
	}
	client("client2", 4)
	handover.SaveConfig = func(c Config) error { saved = c; return nil }
	if e = handover.Begin(cfg, legacySpec, time.Minute); e != nil {
		t.Fatal(e)
	}
	journal, _ := store.HandoverJournal()
	journal.Deadline = time.Now().Unix() - 1
	if e = store.saveHandover(journal); e != nil {
		t.Fatal(e)
	}
	if e = handover.Recover(); e != nil {
		t.Fatal(e)
	}
	client("client2", 4)

	legacy.Stop()
	command("ip", "netns", "exec", "client2", "ip", "addr", "add", "10.77.0.100/24", "dev", "client2p")
	command("ip", "netns", "exec", "client2", "ip", "addr", "add", "10.88.0.1/24", "dev", "lo")
	command("ip", "netns", "exec", "client2", "ip", "-6", "addr", "add", "fd77::100/64", "dev", "client2p", "nodad")
	command("ip", "route", "add", "10.88.0.0/24", "via", "10.77.0.100")
	cfg.Scopes = append(cfg.Scopes,
		Scope{ID: "relay4", Interface: "lab0", Subnet: "10.88.0.0/24", Server: "10.77.0.1", Router: "10.88.0.1", Start: "10.88.0.10", End: "10.88.0.20", Zone: "relay.home.arpa", LeaseSeconds: 600, Enabled: true, Relay: &RelayConfig{Peer: "10.77.0.100", Link: "10.88.0.1"}},
		Scope{ID: "relay6", Interface: "lab0", Subnet: "fd88::/64", Server: "fd77::1", Start: "fd88::10", End: "fd88::20", Zone: "relay.home.arpa", LeaseSeconds: 600, PreferredSeconds: 300, Enabled: true, Relay: &RelayConfig{Peer: "fd77::100", Link: "fd88::1"}, PD: &PDConfig{Prefix: "fd79::/48", Length: 56, Route: true}})
	if e = manager.Apply(cfg, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	relayOut := command("ip", "netns", "exec", "client2", "env", "GHOSTD_RELAY_CLIENT=1", "/lab/test", "-test.run", "^TestRelayClient$", "-test.v")
	t.Log(relayOut)
	// The delegation obtained through the relay is routed via the relay agent.
	var relayed Binding
	for end := time.Now().Add(10 * time.Second); relayed.Address == "" && time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		snap, _ := store.Snapshot("relay6", "", 0)
		for _, b := range snap.Bindings {
			if b.Origin == originPD && b.State == "active" {
				relayed = b
			}
		}
	}
	if relayed.Address == "" || relayed.Via != "fd77::100" || !strings.HasPrefix(relayed.Address, "fd79:") {
		t.Fatalf("relayed delegation missing or not routed via the relay: %+v\n%s", relayed, relayOut)
	}
	for end := time.Now().Add(10 * time.Second); !strings.Contains(command("ip", "-6", "route", "show", "proto", routeProto), relayed.Address) && time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
	}
	if got := command("ip", "-6", "route", "show", "proto", routeProto); !strings.Contains(got, relayed.Address+" via fd77::100") {
		t.Fatalf("relayed prefix %s is not routed via the relay agent:\n%s", relayed.Address, got)
	}

	// Turn on SLAAC explicitly and verify the kernel-generated address is seen
	// as neighbor evidence rather than a DHCP allocation.
	cfg.Scopes[1].RA.SLAAC = true
	if e = manager.Apply(cfg, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	time.Sleep(4 * time.Second)
	command("ip", "netns", "exec", "client2", "rdisc6", "-1", "client2p")
	time.Sleep(2 * time.Second)
	var rows []struct {
		Info []struct {
			Family string   `json:"family"`
			Local  string   `json:"local"`
			Flags  []string `json:"flags"`
		} `json:"addr_info"`
	}
	raw := command("ip", "netns", "exec", "client2", "ip", "-j", "-6", "addr", "show", "dev", "client2p")
	if e = json.Unmarshal([]byte(raw), &rows); e != nil {
		t.Fatal(e)
	}
	slaac := ""
	for _, row := range rows {
		for _, a := range row.Info {
			if strings.HasPrefix(a.Local, "fd77:") && strings.Count(a.Local, ":") > 3 {
				slaac = a.Local
			}
		}
	}
	if slaac == "" {
		t.Fatalf("no kernel SLAAC address: %s", raw)
	}
	command("ip", "netns", "exec", "client2", "ping", "-6", "-I", slaac, "-c", "1", "fd77::1")
	if e = manager.CollectNeighbors(context.Background()); e != nil {
		t.Fatal(e)
	}
	observed, e := store.Snapshot("lan6", slaac, 0)
	if e != nil || len(observed.Observations) != 1 || len(observed.Bindings) != 0 {
		t.Fatalf("SLAAC observation mistaken for grant: %+v %v", observed, e)
	}

	// Prefix delegation to a real router-style client (ISC dhclient -6 -P): the
	// prefix is granted, attributed, routed via the client's link-local address,
	// and the route disappears when the client releases it.
	cfg.Scopes[1].PD = &PDConfig{Prefix: "fd78::/48", Length: 56, Route: true}
	if e = manager.Apply(cfg, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	pdLease, pdPid := filepath.Join(dir, "pd.leases"), filepath.Join(dir, "pd.pid")
	out := command("ip", "netns", "exec", "client2", "dhclient", "-6", "-P", "-1", "-v", "-lf", pdLease, "-pf", pdPid, "client2p")
	t.Log(out)
	var delegated Binding
	for _, b := range func() []Binding { snap, _ := store.Snapshot("lan6", "", 0); return snap.Bindings }() {
		if b.Origin == originPD && b.State == "active" {
			delegated = b
		}
	}
	if delegated.Address == "" || !strings.HasSuffix(delegated.Address, "/56") || !strings.HasPrefix(delegated.Address, "fd78:") || !strings.HasPrefix(delegated.Via, "fe80:") {
		t.Fatalf("no delegated prefix in the ledger: %+v\n%s", delegated, out)
	}
	routeVia := func() string {
		return command("ip", "-6", "route", "show", "proto", routeProto)
	}
	for end := time.Now().Add(10 * time.Second); !strings.Contains(routeVia(), delegated.Address) && time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
	}
	if got := routeVia(); !strings.Contains(got, delegated.Address) || !strings.Contains(got, "via "+delegated.Via) || !strings.Contains(got, "dev lab0") {
		t.Fatalf("delegated prefix %s not routed via %s:\n%s", delegated.Address, delegated.Via, got)
	}
	t.Log(command("ip", "netns", "exec", "client2", "dhclient", "-6", "-P", "-r", "-v", "-lf", pdLease, "-pf", pdPid, "client2p"))
	// dhclient does not wait for the server to process its Release.
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if after, _ := store.Snapshot("lan6", delegated.Address, 0); len(after.Bindings) == 1 && after.Bindings[0].State == "released" {
			break
		}
	}
	if e = manager.ReconcileRoutes(context.Background()); e != nil {
		t.Fatal(e)
	}
	if got := routeVia(); strings.Contains(got, delegated.Address) {
		t.Fatalf("route survived the release:\n%s", got)
	}
	cfg.Scopes[1].PD = nil
	if e = manager.Apply(cfg, func() error { return nil }); e != nil {
		t.Fatal(e)
	}

	// Real, timer-driven DHCPv6 Renew and Rebind. Shorten the lease so T1 is 30s
	// and T2 is 48s, run ISC dhclient -6 in the foreground as a real client, let it
	// renew by itself, then drop its Renews until it falls back to Rebind.
	if os.Getenv("GHOSTD_LAB_SKIP_V6TIMERS") != "1" {
		cfg.Scopes[1].LeaseSeconds, cfg.Scopes[1].PreferredSeconds = 60, 30
		if e = manager.Apply(cfg, func() error { return nil }); e != nil {
			t.Fatal(e)
		}
		for _, f := range []string{"client1-6.pid", "client1-4.pid"} {
			if raw, e := os.ReadFile(filepath.Join(dir, f)); e == nil {
				exec.Command("kill", strings.TrimSpace(string(raw))).Run()
			}
		}
		time.Sleep(500 * time.Millisecond)
		logPath := filepath.Join(dir, "dhclient6-timers.log")
		logFile, _ := os.Create(logPath)
		cli := exec.Command("nsenter", "--net=/run/netns/client1", "--", "dhclient", "-6", "-d", "-v", "-lf", filepath.Join(dir, "timers6.leases"), "-pf", filepath.Join(dir, "timers6.pid"), "client1p")
		cli.Stdout, cli.Stderr = logFile, logFile
		if e = cli.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { cli.Process.Kill(); cli.Wait() })
		count := func(needle string) int {
			raw, _ := os.ReadFile(logPath)
			return strings.Count(string(raw), needle)
		}
		waitFor := func(what string, timeout time.Duration, cond func() bool) {
			t.Helper()
			for end := time.Now().Add(timeout); time.Now().Before(end); time.Sleep(500 * time.Millisecond) {
				if cond() {
					return
				}
			}
			raw, _ := os.ReadFile(logPath)
			t.Fatalf("timed out waiting for %s:\n%s", what, raw)
		}
		waitFor("initial v6 bind", 30*time.Second, func() bool { return count("Bound to lease") >= 1 })
		// The address ISC reports in its own log identifies this client's binding.
		var address string
		iaaddr := regexp.MustCompile(`IAADDR (\S+)`)
		binding := func() Binding {
			raw, _ := os.ReadFile(logPath)
			if m := iaaddr.FindAllStringSubmatch(string(raw), -1); len(m) > 0 {
				address = m[len(m)-1][1]
			}
			snap, _ := store.Snapshot("lan6", address, 0)
			if len(snap.Bindings) == 1 {
				return snap.Bindings[0]
			}
			return Binding{}
		}
		before := binding()
		waitFor("timer-driven Renew answered", 50*time.Second, func() bool { return count("XMT: Renew") >= 1 && count("RCV: Reply") >= 2 })
		afterRenew := binding()
		if afterRenew.End <= before.End {
			t.Fatalf("Renew did not extend the lease: %d -> %d", before.End, afterRenew.End)
		}
		// Drop Renews (UDP 547 into the server) so the client can only Rebind at T2.
		command("nft", "add", "table", "inet", "labdrop")
		command("nft", "add", "chain", "inet", "labdrop", "in", "{ type filter hook input priority 0 ; }")
		command("nft", "add", "rule", "inet", "labdrop", "in", "udp", "dport", "547", "drop")
		t.Cleanup(func() { exec.Command("nft", "delete", "table", "inet", "labdrop").Run() })
		waitFor("client to give up on Renew", 60*time.Second, func() bool { return count("XMT: Renew") >= 3 })
		command("nft", "delete", "table", "inet", "labdrop")
		waitFor("Rebind answered", 60*time.Second, func() bool { return count("XMT: Rebind") >= 1 && count("RCV: Reply") >= 3 })
		afterRebind := binding()
		if afterRebind.End <= afterRenew.End {
			t.Fatalf("Rebind did not extend the lease: %d -> %d", afterRenew.End, afterRebind.End)
		}
		q := new(dns.Msg)
		q.SetQuestion(afterRebind.Name+".lab.home.arpa.", dns.TypeAAAA)
		reply, _, e := (&dns.Client{Net: "udp", Timeout: 2 * time.Second}).Exchange(q, "10.77.0.1:53")
		if e != nil || len(reply.Answer) == 0 {
			t.Fatalf("DNS answer for the rebound lease: %v %v", reply, e)
		}
	}

}
