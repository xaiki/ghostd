//go:build dnsmasq && dhcp

package addressbook

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func fakeFS(files map[string]string, dirs map[string][]string) FileReader {
	return FileReader{
		ReadFile: func(p string) (string, error) {
			if s, ok := files[p]; ok {
				return s, nil
			}
			return "", fmt.Errorf("no such file %s", p)
		},
		ListDir: func(p string) ([]string, error) {
			if d, ok := dirs[p]; ok {
				return d, nil
			}
			return nil, fmt.Errorf("no such dir %s", p)
		},
	}
}
func fakeAddrs(iface string) ([]netip.Prefix, error) {
	switch iface {
	case "eth0":
		return []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("fe80::1/64"), netip.MustParsePrefix("fd00:1::1/64")}, nil
	case "eth1":
		return []netip.Prefix{netip.MustParsePrefix("198.51.100.1/24")}, nil
	}
	return nil, fmt.Errorf("no such interface")
}

const baseConf = `
interface=eth0
bind-interfaces
domain=home.arpa
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
conf-file=/etc/dnsmasq.extra
conf-dir=/etc/dnsmasq.d,.dpkg-dist
`

func convert(t *testing.T, main string, extra map[string]string) (ConvertPlan, error) {
	files := map[string]string{"/etc/dnsmasq.conf": main, "/etc/dnsmasq.extra": "dhcp-range=192.0.2.100,192.0.2.150,255.255.255.0,12h\ndhcp-option=option:router,192.0.2.254\n"}
	dirs := map[string][]string{"/etc/dnsmasq.d": {"/etc/dnsmasq.d/10-hosts.conf", "/etc/dnsmasq.d/.hidden", "/etc/dnsmasq.d/x.dpkg-dist", "/etc/dnsmasq.d/backup~"}}
	files["/etc/dnsmasq.d/10-hosts.conf"] = "dhcp-host=aa:bb:cc:dd:ee:01,192.0.2.110,printer\n"
	files["/etc/dnsmasq.d/.hidden"] = "this is not read\n"
	files["/etc/dnsmasq.d/x.dpkg-dist"] = "nor this\n"
	files["/etc/dnsmasq.d/backup~"] = "nor this\n"
	for k, v := range extra {
		files[k] = v
	}
	return ConvertDNSmasq("/etc/dnsmasq.conf", ConvertOptions{Files: fakeFS(files, dirs), Unit: "dnsmasq.service", Addrs: fakeAddrs})
}

func TestConvertFollowsIncludesAndProducesAValidTakeoverPlan(t *testing.T) {
	plan, e := convert(t, baseConf, nil)
	if e != nil {
		t.Fatal(e)
	}
	s := plan.Target.Scopes[0]
	if s.ID != "eth0" || s.Server != "192.0.2.1" || s.Router != "192.0.2.254" || s.Subnet != "192.0.2.0/24" || s.LeaseSeconds != 43200 || s.Zone != "home.arpa" || !s.Enabled {
		t.Fatal(s)
	}
	if len(s.Reservations) != 1 || s.Reservations[0].Client != "mac:aa:bb:cc:dd:ee:01" || plan.Target.Devices[0].Name != "printer" {
		t.Fatal("reservation from a conf-dir file lost", plan.Target)
	}
	if plan.Legacy.LeasePath != "/var/lib/misc/dnsmasq.leases" || plan.Legacy.Unit != "dnsmasq.service" {
		t.Fatal(plan.Legacy)
	}
	// The plan begins cleanly against a legacy authority.
	m := NewManager(openTest(t))
	defer m.Close()
	target := disabled(plan.Target) // binding eth0 is the lab's job
	h := Handover{Manager: m, Legacy: &memoryLegacy{running: true}, SaveConfig: func(Config) error { return nil }}
	if e = h.Begin(target, plan.Legacy, time.Minute); e != nil {
		t.Fatal(e)
	}
}

func TestConvertIPv6AndRA(t *testing.T) {
	conf := strings.Replace(baseConf, "conf-file=/etc/dnsmasq.extra", "conf-file=/etc/dnsmasq.extra\nenable-ra\ndhcp-range=fd00:1::100,fd00:1::200,64,1h", 1)
	plan, e := convert(t, conf, nil)
	if e != nil {
		t.Fatal(e)
	}
	if len(plan.Target.Scopes) != 2 {
		t.Fatal(plan.Target.Scopes)
	}
	v6 := plan.Target.Scopes[1]
	if v6.ID != "eth0-6" || v6.Server != "fd00:1::1" || v6.RA == nil || v6.PreferredSeconds != 3600 || len(plan.Warnings) == 0 {
		t.Fatal(v6, plan.Warnings)
	}
}

func TestConvertRejectsWhatItCannotPreserve(t *testing.T) {
	cases := map[string]struct {
		conf, want string
	}{
		"unknown directive":   {baseConf + "dhcp-vendorclass=set:pxe,PXEClient\n", "needs explicit conversion"},
		"matching range":      {strings.Replace(baseConf, "domain=home.arpa", "domain=home.arpa\ndhcp-range=tag:guest,198.51.100.10,198.51.100.20,255.255.255.0,1h", 1), "matches on tag:guest"},
		"unknown option":      {baseConf + "dhcp-option=option:sip-server,192.0.2.1\n", "not one this converter"},
		"tagged router away":  {strings.Replace(baseConf, "interface=eth0\n", "interface=eth0\ninterface=eth1\n", 1) + "dhcp-range=set:guest,198.51.100.10,198.51.100.20,255.255.255.0,1h\ndhcp-option=tag:guest,option:router,192.0.2.254\n", "outside"},
		"bad option value":    {baseConf + "dhcp-option=option:ntp-server,not-an-ip\n", "not an IPv4"},
		"infinite lease":      {strings.Replace(baseConf, "domain=home.arpa", "domain=home.arpa\ndhcp-range=192.0.2.200,192.0.2.210,255.255.255.0,infinite", 1), "infinite leases"},
		"no zone":             {strings.Replace(baseConf, "domain=home.arpa\n", "", 1), "no domain="},
		"host outside pool":   {baseConf + "dhcp-host=aa:bb:cc:dd:ee:02,203.0.113.5,elsewhere\n", "outside every converted range"},
		"no lease file":       {strings.Replace(baseConf, "dhcp-leasefile=/var/lib/misc/dnsmasq.leases\n", "", 1), "dhcp-leasefile"},
		"interface excluded":  {baseConf + "no-dhcp-interface=eth0\n", "no listed interface"},
		"no interface listed": {strings.Replace(baseConf, "interface=eth0\n", "", 1), "no listed interface"},
		"include cycle":       {baseConf + "conf-file=/etc/dnsmasq.conf\n", "cycle"},
		"missing include":     {baseConf + "conf-file=/etc/nope.conf\n", "no such file"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := convert(t, c.conf, nil); e == nil || !strings.Contains(e.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, e)
			}
		})
	}
}

func TestValidatorFollowsIncludesAndExclusions(t *testing.T) {
	plan, e := convert(t, baseConf, nil)
	if e != nil {
		t.Fatal(e)
	}
	text, _ := FlattenDNSmasq("/etc/dnsmasq.conf", fakeFS(map[string]string{"/etc/dnsmasq.conf": baseConf + "conf-file=/etc/x\n", "/etc/dnsmasq.extra": "dhcp-range=192.0.2.100,192.0.2.150,255.255.255.0,12h\ndhcp-option=option:router,192.0.2.254\n", "/etc/x": "except-interface=eth0\n", "/etc/dnsmasq.d/10-hosts.conf": "dhcp-host=aa:bb:cc:dd:ee:01,192.0.2.110,printer\n"}, map[string][]string{"/etc/dnsmasq.d": {"/etc/dnsmasq.d/10-hosts.conf"}}))
	if e = ValidateDNSmasqConfig(plan.Target, text, plan.Legacy.LeasePath); e == nil || !strings.Contains(e.Error(), "excludes") {
		t.Fatal("a scope on an interface the legacy config excludes from DHCP was accepted:", e)
	}
}

func TestConvertTagsMultiValueAndGenericOptions(t *testing.T) {
	conf := strings.Replace(baseConf, "interface=eth0\n", "interface=eth0\ninterface=eth1\n", 1) + `
dhcp-range=set:guest,198.51.100.10,198.51.100.20,255.255.255.0,1h
dhcp-option=tag:guest,option:router,198.51.100.254
dhcp-option=tag:guest,option:dns-server,198.51.100.1,9.9.9.9
dhcp-option=option:ntp-server,192.0.2.1,198.51.100.1
dhcp-option=26,1400
`
	plan, err := convert(t, conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Target.Scopes) != 2 {
		t.Fatal(plan.Target.Scopes)
	}
	lan, guest := plan.Target.Scopes[0], plan.Target.Scopes[1]
	if lan.Router != "192.0.2.254" || len(lan.DNSServers) != 0 {
		t.Fatal("untagged scope must not pick up the guest-tagged options:", lan)
	}
	if guest.Router != "198.51.100.254" || len(guest.DNSServers) != 2 || guest.DNSServers[1] != "9.9.9.9" {
		t.Fatal("tagged options did not reach their range:", guest)
	}
	for _, sc := range []Scope{lan, guest} {
		if len(sc.Options) != 2 || sc.Options[0].Code != 26 || sc.Options[1].Code != 42 || sc.Options[1].Value[1] != "198.51.100.1" {
			t.Fatal("global generic options reach every scope:", sc.Options)
		}
	}
	// The plan is accepted by the takeover validator, and a drifted target is not.
	text, _ := FlattenDNSmasq("/etc/dnsmasq.conf", fakeFSFor(conf))
	if e := ValidateDNSmasqConfig(plan.Target, text, plan.Legacy.LeasePath); e != nil {
		t.Fatal(e)
	}
	drift := cloneConfig(plan.Target)
	drift.Scopes[1].DNSServers = nil
	if e := ValidateDNSmasqConfig(drift, text, plan.Legacy.LeasePath); e == nil {
		t.Fatal("a target that dropped the tagged DNS servers was accepted")
	}
	drift = cloneConfig(plan.Target)
	drift.Scopes[0].Options = drift.Scopes[0].Options[:1]
	if e := ValidateDNSmasqConfig(drift, text, plan.Legacy.LeasePath); e == nil {
		t.Fatal("a target that dropped an option was accepted")
	}
}

func fakeFSFor(main string) FileReader {
	files := map[string]string{"/etc/dnsmasq.conf": main, "/etc/dnsmasq.extra": "dhcp-range=192.0.2.100,192.0.2.150,255.255.255.0,12h\ndhcp-option=option:router,192.0.2.254\n"}
	return fakeFS(files, map[string][]string{"/etc/dnsmasq.d": {}})
}
