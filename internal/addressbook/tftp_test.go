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

func TestBootOptionsInDHCPReplies(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	c.Scopes[0].Boot = &BootConfig{File: "pxelinux.0"}
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	discover, _ := dhcpv4.NewDiscovery(mac)
	offer, err := s.Handle4(c, c.Scopes[0], discover)
	if err != nil || offer == nil {
		t.Fatal(err)
	}
	if offer.BootFileName != "pxelinux.0" || offer.BootFileNameOption() != "pxelinux.0" || !offer.ServerIPAddr.Equal(net.ParseIP("10.0.0.1")) || offer.TFTPServerName() != "10.0.0.1" {
		t.Fatalf("boot hand-off missing: file=%q siaddr=%v opt66=%q", offer.BootFileName, offer.ServerIPAddr, offer.TFTPServerName())
	}
	c.Scopes[0].Boot.NextServer = "10.0.0.9"
	offer, _ = s.Handle4(c, c.Scopes[0], discover)
	if !offer.ServerIPAddr.Equal(net.ParseIP("10.0.0.9")) || offer.TFTPServerName() != "10.0.0.9" {
		t.Fatal("explicit next server ignored", offer.ServerIPAddr)
	}
	c.Scopes[0].Boot = nil
	if plain, _ := s.Handle4(c, c.Scopes[0], discover); plain.BootFileName != "" || len(plain.ServerIPAddr) != 0 && !plain.ServerIPAddr.IsUnspecified() {
		t.Fatal("boot fields present without configuration")
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

func TestConvertCarriesBootAndTFTP(t *testing.T) {
	conf := baseConf + "dhcp-boot=pxelinux.0\nenable-tftp\ntftp-root=/srv/tftp\n"
	plan, err := convert(t, conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b := plan.Target.Scopes[0].Boot; b == nil || b.File != "pxelinux.0" || b.NextServer != "" || plan.Target.TFTP == nil || plan.Target.TFTP.Root != "/srv/tftp" {
		t.Fatal(plan.Target)
	}
	plan, err = convert(t, baseConf+"dhcp-boot=lpxelinux.0,,192.0.2.9\n", nil) // file,servername,address
	if err != nil || plan.Target.Scopes[0].Boot.NextServer != "192.0.2.9" {
		t.Fatal(err)
	}
	plan, err = convert(t, baseConf+"dhcp-boot=lpxelinux.0,192.0.2.9\n", nil)
	if err != nil || plan.Target.Scopes[0].Boot.NextServer != "192.0.2.9" {
		t.Fatal(err, plan.Target.Scopes[0].Boot)
	}
	for name, bad := range map[string]string{
		"tftp without root": baseConf + "enable-tftp\n",
		"interface tftp":    baseConf + "enable-tftp=eth0\ntftp-root=/srv\n",
		"tagged boot":       baseConf + "dhcp-boot=tag:pxe,pxelinux.0\n",
	} {
		if _, err := convert(t, bad, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
