package addressbook

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ParseDNSmasq preserves v4 client IDs, v6 DUID/IAID, expiry and server DUID.
// Unknown/ambiguous scopes are errors: silently dropping a lease is unsafe.
func ParseDNSmasq(c Config, text string) (ImportDocument, error) {
	doc := ImportDocument{}
	for n, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) == 2 && f[0] == "duid" {
			doc.ServerDUID = strings.ReplaceAll(f[1], ":", "")
			continue
		}
		if len(f) != 5 {
			return doc, fmt.Errorf("lease line %d: expected five fields", n+1)
		}
		ip, e := netip.ParseAddr(f[2])
		if e != nil {
			return doc, e
		}
		expiry, e := strconv.ParseInt(f[0], 10, 64)
		if e != nil || expiry < 0 {
			return doc, fmt.Errorf("invalid lease expiry")
		}
		l := ImportedLease{Address: ip.String(), Expiry: expiry, Hostname: f[3]}
		if l.Hostname == "*" {
			l.Hostname = ""
		}
		for _, s := range c.Scopes {
			if netip.MustParsePrefix(s.Subnet).Contains(ip) {
				if l.Scope != "" {
					return doc, fmt.Errorf("ambiguous lease scope")
				}
				l.Scope = s.ID
			}
		}
		if l.Scope == "" {
			return doc, fmt.Errorf("lease %s has no declared scope", ip)
		}
		if ip.Is6() {
			iaid, e := strconv.ParseUint(f[1], 10, 32)
			if e != nil {
				return doc, fmt.Errorf("unsupported DHCPv6 IAID (temporary addresses are not IA_NA)")
			}
			l.IAID = fmt.Sprintf("%08x", iaid)
			l.DUID = strings.ReplaceAll(f[4], ":", "")
		} else {
			l.MAC = f[1]
			l.ClientID = f[4]
		}
		doc.Leases = append(doc.Leases, l)
	}
	return doc, nil
}
func colonHex(value string) string {
	var fields []string
	for i := 0; i+1 < len(value); i += 2 {
		fields = append(fields, value[i:i+2])
	}
	return strings.Join(fields, ":")
}

// ExportDNSmasq includes offers/quarantine as occupied until expiry. Declined
// addresses use an unrelated synthetic identity so the declining client cannot
// reacquire them during quarantine through dnsmasq's renewal path.
func ExportDNSmasq(snapshot Snapshot) (string, error) {
	var lines []string
	if snapshot.ServerDUID != "" {
		lines = append(lines, "duid "+colonHex(snapshot.ServerDUID))
	}
	for _, b := range snapshot.Bindings {
		if b.State != "active" && b.State != "offered" && b.State != "declined" {
			continue
		}
		if b.Origin == "neighbor-report" || b.Origin == originPD {
			continue // no legacy lease-file form: a delegation cannot be handed back to dnsmasq
		}
		expiry := b.End
		if expiry == 253402300799 {
			expiry = 0
		}
		name := b.Name
		if !labelPattern.MatchString(name) {
			name = "*"
		}
		ip, e := netip.ParseAddr(b.Address)
		if e != nil {
			return "", e
		}
		if ip.Is6() {
			iaid, e := strconv.ParseUint(b.IAID, 16, 32)
			if e != nil {
				return "", e
			}
			duid := b.DUID
			if b.State == "declined" {
				sum := sha256.Sum256([]byte(b.Scope + "/" + b.Address))
				duid = "0004" + hex.EncodeToString(sum[:16])
			}
			lines = append(lines, fmt.Sprintf("%d %d %s %s %s", expiry, iaid, b.Address, name, colonHex(duid)))
		} else {
			client := "*"
			if strings.HasPrefix(b.Client, "id:") {
				client = colonHex(strings.TrimPrefix(b.Client, "id:"))
			}
			mac := b.MAC
			if b.State == "declined" {
				mac = "02:ff:ff:ff:ff:fe"
				client = "ff:" + colonHex(hex.EncodeToString([]byte(b.Address)))
			}
			lines = append(lines, fmt.Sprintf("%d %s %s %s %s", expiry, mac, b.Address, name, client))
		}
	}
	return strings.Join(lines, "\n") + "\n", nil
}
