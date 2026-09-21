//go:build dhcp && dnsmasq && linux

package addressbook

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
)

// probeDHCP is a real DORA on the wire as a synthetic client.
func probeDHCP(ctx context.Context, p Probe, c Config) (string, error) {
	sc, _ := c.Scope(p.Scope)
	mac := make(net.HardwareAddr, 6)
	if _, err := rand.Read(mac); err != nil {
		return "", err
	}
	copy(mac, []byte{0x02, 0x67, 0x68, 0x6f, 0x73}) // probeMACPrefix
	// A host does not hear its own frames on its own interface, so a probe on the
	// scope's interface would never reach the listener bound to it. On a bridge
	// (container networks, VLAN bridges) the probe client gets a veth pair: one end
	// is a port of the bridge, the other is the client's own interface, which is
	// what a real neighbour looks like.
	iface, cleanup, err := probeInterface(ctx, sc.Interface, mac)
	if err != nil {
		return "", err
	}
	defer cleanup()
	client, err := nclient4.New(iface, nclient4.WithHWAddr(mac), nclient4.WithTimeout(3*time.Second), nclient4.WithRetry(2))
	if err != nil {
		return "", fmt.Errorf("open %s: %w", iface, err)
	}
	defer client.Close()
	lease, err := client.Request(ctx, dhcpv4.WithOption(dhcpv4.OptHostName("ghostd-probe")))
	if err != nil {
		hint := ""
		if iface == sc.Interface {
			hint = " (a host cannot hear its own frames on a physical interface; probe from another host, or put the scope on a bridge)"
		}
		return "", fmt.Errorf("DORA on %s: %w%s", sc.Interface, err, hint)
	}
	defer client.Release(lease)
	ack := lease.ACK
	prefix := netip.MustParsePrefix(sc.Subnet)
	addr, _ := netip.AddrFromSlice(ack.YourIPAddr.To4())
	if !prefix.Contains(addr) {
		return "", fmt.Errorf("leased %s is outside %s", addr, prefix)
	}
	if routers := ack.Router(); len(routers) == 0 || routers[0].String() != sc.Router {
		return "", fmt.Errorf("router option %v, want %s", routers, sc.Router)
	}
	want := sc.DNSServers
	if len(want) == 0 {
		want = []string{sc.Server}
	}
	got := ack.DNS()
	if len(got) != len(want) {
		return "", fmt.Errorf("DNS option %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			return "", fmt.Errorf("DNS option %v, want %v", got, want)
		}
	}
	name, err := verifyLeaseThroughDNS(ctx, sc, addr)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("DORA on %s leased %s (router %s, DNS %v); %s resolves both ways", sc.Interface, addr, sc.Router, want, name), nil
}

// probeInterface returns the interface the synthetic client should use, and how
// to remove it.
func probeInterface(ctx context.Context, ifname string, mac net.HardwareAddr) (string, func(), error) {
	if _, err := os.Stat("/sys/class/net/" + ifname + "/bridge"); err != nil {
		return ifname, func() {}, nil
	}
	suffix := fmt.Sprintf("%02x%02x", mac[4], mac[5])
	port, client := "gpa"+suffix, "gpb"+suffix
	run := func(args ...string) error {
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	cleanup := func() { exec.Command("ip", "link", "del", port).Run() }
	if err := run("link", "add", port, "type", "veth", "peer", "name", client); err != nil {
		return "", nil, err
	}
	for _, args := range [][]string{
		{"link", "set", client, "address", mac.String()},
		{"link", "set", port, "master", ifname}, {"link", "set", port, "up"}, {"link", "set", client, "up"},
	} {
		if err := run(args...); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	time.Sleep(300 * time.Millisecond) // let the bridge port forward
	return client, cleanup, nil
}
