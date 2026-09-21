//go:build dhcp && dnsmasq

package addressbook

import (
	"testing"
)

func TestV6DNSmasqImportIdentityAndRollback(t *testing.T) {
	s := openTest(t)
	c := disabled(config6())
	text := "duid 00:03:00:01:00:11:22:33:44:55\n0 4294967295 fd00::6 host 00:03:00:01:00:11:22:33:44:66\n"
	doc, e := ParseDNSmasq(c, text)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.ImportDocument(c, doc); e != nil {
		t.Fatal(e)
	}
	snap, _ := s.Snapshot("", "", 0)
	if snap.Bindings[0].IAID != "ffffffff" || snap.Bindings[0].End != 253402300799 {
		t.Fatal(snap)
	}
	exported, e := ExportDNSmasq(snap)
	if e != nil {
		t.Fatal(e)
	}
	round, e := ParseDNSmasq(c, exported)
	if e != nil || round.ServerDUID != doc.ServerDUID || round.Leases[0].DUID != doc.Leases[0].DUID {
		t.Fatal(round, e)
	}
	doc.ServerDUID = "00030001001122334477"
	if e = s.ImportDocument(c, doc); e == nil {
		t.Fatal("server identity changed under existing grants")
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
	plan, err = convert(t, baseConf+"enable-tftp=eth0,eth1\ntftp-root=/srv/tftp\n", nil)
	if err != nil || plan.Target.TFTP == nil || len(plan.Target.TFTP.Interfaces) != 2 || plan.Target.TFTP.Interfaces[0] != "eth0" {
		t.Fatal("interface-limited TFTP:", err, plan.Target.TFTP)
	}
	for name, bad := range map[string]string{
		"tftp without root": baseConf + "enable-tftp\n",
		"tagged boot":       baseConf + "dhcp-boot=tag:pxe,pxelinux.0\n",
	} {
		if _, err := convert(t, bad, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
