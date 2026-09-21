//go:build dhcp

package addressbook

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/pin/tftp/v3"
)

func tftpFixture(t *testing.T) (client *tftp.Client, root string) {
	t.Helper()
	root = t.TempDir()
	os.MkdirAll(filepath.Join(root, "boot"), 0755)
	os.WriteFile(filepath.Join(root, "pxe.bin"), bytes.Repeat([]byte("x"), 5000), 0644)
	os.WriteFile(filepath.Join(root, "boot", "grub.cfg"), []byte("menu\n"), 0644)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("secret\n"), 0644)
	os.Symlink(outside, filepath.Join(root, "escape"))
	os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "leak"))
	os.Symlink("pxe.bin", filepath.Join(root, "alias.bin")) // a symlink that stays inside is fine
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newTFTP(root, conn)
	t.Cleanup(srv.close)
	c, err := tftp.NewClient(conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c, root
}
func fetch(c *tftp.Client, name string) ([]byte, error) {
	w, err := c.Receive(name, "octet")
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	_, err = w.WriteTo(&b)
	return b.Bytes(), err
}

func TestTFTPServesOnlyRegularFilesBeneathItsRoot(t *testing.T) {
	c, _ := tftpFixture(t)
	if got, err := fetch(c, "pxe.bin"); err != nil || len(got) != 5000 {
		t.Fatal("legitimate boot file:", len(got), err)
	}
	if got, err := fetch(c, "boot/grub.cfg"); err != nil || string(got) != "menu\n" {
		t.Fatal(err)
	}
	if got, err := fetch(c, "alias.bin"); err != nil || len(got) != 5000 {
		t.Fatal("inward symlink refused:", err)
	}
	for _, bad := range []string{"../../etc/passwd", "/etc/passwd", "boot/../../etc/passwd", "escape/secret", "leak", "boot", "missing", "", "..\\..\\etc\\passwd"} {
		if got, err := fetch(c, bad); err == nil {
			t.Errorf("%q was served (%d bytes)", bad, len(got))
		}
	}
}

func TestTFTPRefusesWrites(t *testing.T) {
	c, root := tftpFixture(t)
	if w, err := c.Send("upload.bin", "octet"); err == nil {
		_, err = w.ReadFrom(strings.NewReader("evil"))
		if err == nil {
			t.Fatal("write accepted")
		}
	}
	if _, err := os.Stat(filepath.Join(root, "upload.bin")); err == nil {
		t.Fatal("file created by a TFTP write")
	}
}

func TestBootOptionsGoOnlyToClientsThatAsk(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	c.Scopes[0].Boot = &BootConfig{File: "pxelinux.0"}
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	offerTo := func(mods ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
		t.Helper()
		discover, _ := dhcpv4.NewDiscovery(mac, mods...)
		offer, err := s.Handle4(c, c.Scopes[0], discover)
		if err != nil || offer == nil {
			t.Fatal(err)
		}
		return offer
	}
	if o := offerTo(); o.BootFileName != "" || o.TFTPServerName() != "" || len(o.ServerIPAddr) != 0 && !o.ServerIPAddr.IsUnspecified() {
		t.Fatalf("a client that did not ask was handed boot fields: %q %v", o.BootFileName, o.ServerIPAddr)
	}
	for name, mod := range map[string]dhcpv4.Modifier{
		"requests option 67": dhcpv4.WithRequestedOptions(dhcpv4.OptionBootfileName),
		"requests option 66": dhcpv4.WithRequestedOptions(dhcpv4.OptionTFTPServerName),
		"PXEClient":          dhcpv4.WithOption(dhcpv4.OptClassIdentifier("PXEClient:Arch:00007:UNDI:003016")),
	} {
		o := offerTo(mod)
		if o.BootFileName != "pxelinux.0" || o.BootFileNameOption() != "pxelinux.0" || !o.ServerIPAddr.Equal(net.ParseIP("10.0.0.1")) || o.TFTPServerName() != "10.0.0.1" {
			t.Fatalf("%s: boot hand-off missing: file=%q siaddr=%v opt66=%q", name, o.BootFileName, o.ServerIPAddr, o.TFTPServerName())
		}
	}
	c.Scopes[0].Boot.Always = true
	if o := offerTo(); o.BootFileName != "pxelinux.0" {
		t.Fatal("always must send the boot fields to everyone")
	}
	c.Scopes[0].Boot.Always = false
	c.Scopes[0].Boot.NextServer = "10.0.0.9"
	if o := offerTo(dhcpv4.WithOption(dhcpv4.OptClassIdentifier("PXEClient"))); !o.ServerIPAddr.Equal(net.ParseIP("10.0.0.9")) || o.TFTPServerName() != "10.0.0.9" {
		t.Fatal("explicit next server ignored", o.ServerIPAddr)
	}
	c.Scopes[0].Boot = nil
	if o := offerTo(dhcpv4.WithOption(dhcpv4.OptClassIdentifier("PXEClient"))); o.BootFileName != "" {
		t.Fatal("boot fields present without configuration")
	}
}

func TestScopeDNSServersAndExtraOptionsOnTheWire(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	c.Scopes[0].DNSServers = []string{"10.0.0.1", "9.9.9.9"}
	c.Scopes[0].Options = []DHCPOption{{Code: 42, Type: "ips", Value: []string{"10.0.0.2"}}, {Code: 26, Type: "u16", Value: []string{"1400"}}, {Code: 224, Type: "text", Value: []string{"site-a"}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	discover, _ := dhcpv4.NewDiscovery(mac)
	o, err := s.Handle4(c, c.Scopes[0], discover)
	if err != nil || o == nil {
		t.Fatal(err)
	}
	if dns := o.DNS(); len(dns) != 2 || dns[1].String() != "9.9.9.9" {
		t.Fatal("DNS servers:", dns)
	}
	if got := o.Options.Get(dhcpv4.GenericOptionCode(42)); len(got) != 4 || got[3] != 2 {
		t.Fatal("ntp option:", got)
	}
	if got := o.Options.Get(dhcpv4.GenericOptionCode(26)); len(got) != 2 || got[0] != 0x05 || got[1] != 0x78 {
		t.Fatal("mtu option:", got)
	}
	if got := o.Options.Get(dhcpv4.GenericOptionCode(224)); string(got) != "site-a" {
		t.Fatal("text option:", got)
	}
	for name, mut := range map[string]func(*Scope){
		"reserved code": func(s *Scope) { s.Options = []DHCPOption{{Code: 51, Type: "u32", Value: []string{"1"}}} },
		"router code":   func(s *Scope) { s.Options = []DHCPOption{{Code: 3, Type: "ips", Value: []string{"10.0.0.1"}}} },
		"duplicate": func(s *Scope) {
			s.Options = []DHCPOption{{Code: 42, Type: "ips", Value: []string{"10.0.0.2"}}, {Code: 42, Type: "ips", Value: []string{"10.0.0.3"}}}
		},
		"bad ip":         func(s *Scope) { s.Options = []DHCPOption{{Code: 42, Type: "ips", Value: []string{"x"}}} },
		"u16 overflow":   func(s *Scope) { s.Options = []DHCPOption{{Code: 26, Type: "u16", Value: []string{"70000"}}} },
		"bad dns server": func(s *Scope) { s.DNSServers = []string{"fd00::1"} },
	} {
		bad := cloneConfig(c)
		mut(&bad.Scopes[0])
		if err := bad.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	v6 := config6()
	v6.Scopes[0].Options = []DHCPOption{{Code: 42, Type: "ips", Value: []string{"10.0.0.2"}}}
	if err := v6.Validate(); err == nil {
		t.Fatal("options on an IPv6 scope accepted")
	}
}

func TestBootAndTFTPConfigValidation(t *testing.T) {
	ok := testConfig()
	ok.Scopes[0].Boot = &BootConfig{File: "pxe.bin", NextServer: "10.0.0.2"}
	ok.TFTP = &TFTPConfig{Root: "/srv/tftp"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	mutate := map[string]func(*Config){
		"empty boot file":    func(c *Config) { c.Scopes[0].Boot.File = "" },
		"newline in file":    func(c *Config) { c.Scopes[0].Boot.File = "a\nb" },
		"v6 next server":     func(c *Config) { c.Scopes[0].Boot.NextServer = "fd00::1" },
		"multicast next":     func(c *Config) { c.Scopes[0].Boot.NextServer = "224.0.0.1" },
		"relative tftp root": func(c *Config) { c.TFTP.Root = "srv/tftp" },
		"root is /":          func(c *Config) { c.TFTP.Root = "/" },
		"unclean tftp root":  func(c *Config) { c.TFTP.Root = "/srv/../etc" },
	}
	for name, m := range mutate {
		c := cloneConfig(ok)
		m(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	v6 := config6()
	v6.Scopes[0].Boot = &BootConfig{File: "x"}
	if err := v6.Validate(); err == nil {
		t.Fatal("IPv6 scope with network boot accepted")
	}
	// The config must survive a JSON round trip, and cloning must not alias.
	raw, _ := jsonMarshal(ok)
	back, err := ParseConfig(raw)
	if err != nil || back.Scopes[0].Boot == nil || back.TFTP == nil {
		t.Fatal(err)
	}
	cl := cloneConfig(ok)
	cl.Scopes[0].Boot.File = "changed"
	cl.TFTP.Root = "/other"
	if ok.Scopes[0].Boot.File != "pxe.bin" || ok.TFTP.Root != "/srv/tftp" {
		t.Fatal("clone aliases boot/tftp")
	}
}
