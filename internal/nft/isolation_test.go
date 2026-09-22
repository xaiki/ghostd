package nft

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/xaiki/ghostd/internal/wellknown"
)

// Invoked by the parent test inside a client network namespace.
func TestIntegrationPacketProbe(t *testing.T) {
	target := os.Getenv("GHOSTD_PACKET_TARGET")
	if target == "" {
		t.Skip("client subprocess only")
	}
	proto := os.Getenv("GHOSTD_PACKET_PROTO")
	conn, err := net.DialTimeout(proto, target, 500*time.Millisecond)
	if err == nil {
		defer conn.Close()
		if proto == "udp" {
			conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			_, err = conn.Write([]byte("probe"))
			if err == nil {
				var reply [32]byte
				_, err = conn.Read(reply[:])
			}
		}
	}
	allowed := os.Getenv("GHOSTD_PACKET_ALLOW") == "1"
	if (err == nil) != allowed {
		t.Fatalf("%s %s: allowed=%v, got %v", proto, target, allowed, err)
	}
}

// Real listeners and packets, not just a textual assertion about rules. Run in
// a disposable Linux VM under unshare -n: this also creates temporary netns.
func TestIntegrationGuestCannotReachLANServices(t *testing.T) {
	if os.Getenv("GHOSTD_NFT_INTEGRATION") != "1" {
		t.Skip("requires disposable Linux network namespaces")
	}
	ctx := context.Background()
	command := func(args ...string) {
		t.Helper()
		cmd := exec.Command("ip", args...)
		if len(args) >= 2 && args[0] == "-n" {
			// Enter only the network namespace; ip -n also remounts /sys,
			// which is unnecessary and unavailable in nested rootless tests.
			cmd = exec.Command("nsenter", append([]string{"--net=/var/run/netns/" + args[1], "ip"}, args[2:]...)...)
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	command("link", "set", "lo", "up")
	names := map[string]string{}
	for i, zone := range []string{"guest", "lan"} {
		ns := fmt.Sprintf("ghostd-%s-%d", zone, os.Getpid())
		dev := "gd-" + zone
		names[zone] = ns
		command("netns", "add", ns)
		defer exec.Command("ip", "netns", "delete", ns).Run()
		command("link", "add", dev, "type", "veth", "peer", "name", dev+"-peer")
		command("link", "set", dev+"-peer", "netns", ns)
		subnet := fmt.Sprintf("192.0.%d", 2+i)
		command("addr", "add", subnet+".1/24", "dev", dev)
		command("link", "set", dev, "up")
		command("-n", ns, "addr", "add", subnet+".2/24", "dev", dev+"-peer")
		command("-n", ns, "link", "set", dev+"-peer", "up")
		command("-n", ns, "route", "add", "default", "via", subnet+".1")
	}
	for _, port := range []int{22, 53, 2049, 18080, 8443} {
		listener, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}(listener)
	}
	for _, port := range []int{wellknown.PortTFTP, wellknown.PortMDNS, 15514} {
		listener, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func(l net.PacketConn) {
			var b [32]byte
			for {
				n, addr, err := l.ReadFrom(b[:])
				if err != nil {
					return
				}
				l.WriteTo(b[:n], addr)
			}
		}(listener)
	}
	ds := DesiredState{Zones: map[string]Zone{
		"guest": {Interfaces: []string{"gd-guest"}, Ports: []PortRule{{Port: wellknown.PortDNS, Proto: "tcp"}, {Port: wellknown.PortMDNS, Proto: "udp"}}},
		"lan":   {Interfaces: []string{"gd-lan"}, SSH: &SSHRule{Port: 22}, Ports: []PortRule{{Port: wellknown.PortNFS, Proto: "tcp"}}, Redirects: []RedirectRule{{Port: 514, ToPort: 15514, Proto: "udp"}}},
	}, Ingress: &Ingress{Interfaces: []string{"gd-lan"}, Redirects: []RedirectRule{
		{Port: wellknown.PortHTTP, ToPort: 18080, Proto: "tcp"}, {Port: wellknown.PortHTTPS, ToPort: 8443, Proto: "tcp"}}}}
	script, err := Render(ds, guard())
	if err != nil {
		t.Fatal(err)
	}
	if err := Commit(ctx, ExecRunner{}, script); err != nil {
		t.Fatal(err)
	}
	defer Restore(ctx, ExecRunner{}, []byte(`{"nftables":[]}`))
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probe := func(zone, proto, address string, allow bool) {
		t.Helper()
		cmd := exec.Command("nsenter", "--net=/var/run/netns/"+names[zone], exe, "-test.run=^TestIntegrationPacketProbe$", "-test.v")
		flag := "0"
		if allow {
			flag = "1"
		}
		cmd.Env = append(os.Environ(), "GHOSTD_PACKET_TARGET="+address, "GHOSTD_PACKET_PROTO="+proto, "GHOSTD_PACKET_ALLOW="+flag)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s probe: %v: %s", zone, err, out)
		}
	}
	probe("guest", "tcp", wellknown.HostPort("192.0.2.1", wellknown.PortDNS), true)
	probe("guest", "udp", wellknown.HostPort("192.0.2.1", wellknown.PortMDNS), true)
	for _, port := range []int{22, wellknown.PortNFS, 18080, 8443} {
		probe("guest", "tcp", fmt.Sprintf("192.0.2.1:%d", port), false)
	}
	probe("guest", "udp", wellknown.HostPort("192.0.2.1", wellknown.PortTFTP), false)
	// Even addressing the router's LAN IP cannot escape the incoming guest zone.
	probe("guest", "tcp", wellknown.HostPort("192.0.3.1", wellknown.PortNFS), false)
	probe("lan", "tcp", wellknown.HostPort("192.0.3.1", wellknown.PortNFS), true)
	probe("lan", "tcp", wellknown.HostPort("192.0.3.1", wellknown.PortHTTP), true)
	probe("lan", "tcp", wellknown.HostPort("192.0.3.1", wellknown.PortHTTPS), true)
	probe("lan", "udp", "192.0.3.1:514", true)
	probe("lan", "udp", "192.0.3.1:15514", false)
	probe("guest", "udp", "192.0.2.1:514", false)
	probe("guest", "udp", "192.0.3.1:514", false)
	// A host with no ghostd filtering can adopt only the redirect. Its existing
	// filter table must still decide unrelated access after the transaction.
	if err := Restore(ctx, ExecRunner{}, []byte(`{"nftables":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := Commit(ctx, ExecRunner{}, `table inet migration_existing {
 chain input { type filter hook input priority 0; policy accept; tcp dport 22 drop; }
}`); err != nil {
		t.Fatal(err)
	}
	defer Commit(ctx, ExecRunner{}, "delete table inet migration_existing")
	narrow := DesiredState{RedirectOnly: true, Zones: map[string]Zone{"services": {Interfaces: []string{"gd-lan"}, Redirects: []RedirectRule{{Port: 514, ToPort: 15514, Proto: "udp"}}}}}
	script, err = Render(narrow, guard())
	if err != nil {
		t.Fatal(err)
	}
	if err := Commit(ctx, ExecRunner{}, script); err != nil {
		t.Fatal(err)
	}
	probe("lan", "udp", "192.0.3.1:514", true)
	probe("guest", "tcp", "192.0.2.1:22", false)
	probe("guest", "tcp", wellknown.HostPort("192.0.2.1", wellknown.PortDNS), true)

}
