//go:build dhcp && dnsmasq

package addressbook

import (
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// dnsmasq DHCP options the converter and the takeover validator understand, by
// name and by number. Anything else is refused rather than guessed at.
var knownDHCPOptions = map[string]struct {
	code int
	typ  string
}{
	"router": {3, "ips"}, "dns-server": {6, "ips"}, "time-server": {4, "ips"}, "log-server": {7, "ips"},
	"lpr-server": {9, "ips"}, "mtu": {26, "u16"}, "ntp-server": {42, "ips"}, "netbios-ns": {44, "ips"},
}

// dmOption is one parsed dhcp-option directive.
type dmOption struct {
	tag  string // "" for an untagged, global option
	code int
	typ  string
	vals []string
}

// parseDHCPOption parses "[tag:X,]option:name,v1,v2" and "[tag:X,]NN,v1,v2".
func parseDHCPOption(value string) (dmOption, error) {
	f := strings.Split(value, ",")
	o := dmOption{}
	if len(f) > 0 && strings.HasPrefix(f[0], "tag:") {
		o.tag = strings.TrimPrefix(f[0], "tag:")
		f = f[1:]
	}
	if len(f) < 2 {
		return o, fmt.Errorf("option %q has no value", value)
	}
	key, vals := f[0], f[1:]
	if strings.HasPrefix(key, "option:") {
		k, ok := knownDHCPOptions[strings.TrimPrefix(key, "option:")]
		if !ok {
			return o, fmt.Errorf("option %s is not one this converter carries over (%s)", key, knownNames())
		}
		o.code, o.typ = k.code, k.typ
	} else {
		n, err := strconv.Atoi(key)
		if err != nil {
			return o, fmt.Errorf("unsupported option %q", key)
		}
		found := false
		for _, k := range knownDHCPOptions {
			if k.code == n {
				o.code, o.typ, found = n, k.typ, true
			}
		}
		if !found {
			return o, fmt.Errorf("option %d is not one this converter carries over (%s)", n, knownNames())
		}
	}
	o.vals = vals
	return o, (DHCPOption{Code: o.code, Type: o.typ, Value: vals}).validateAny()
}

func knownNames() string {
	var n []string
	for k := range knownDHCPOptions {
		n = append(n, k)
	}
	sort.Strings(n)
	return "known: " + strings.Join(n, ", ")
}

// validateAny is validate() without the reserved-code rule: router and DNS
// server are carried by their own scope fields.
func (o DHCPOption) validateAny() error {
	if o.Code == 3 || o.Code == 6 {
		for _, v := range o.Value {
			if a, e := netip.ParseAddr(v); e != nil || !a.Is4() {
				return fmt.Errorf("option %d: %q is not an IPv4 address", o.Code, v)
			}
		}
		return nil
	}
	return o.validate()
}

// scopeSettings is what a set of dhcp-option lines means for one scope.
type scopeSettings struct {
	router string
	dns    []string // nil = the scope's own server
	others []DHCPOption
}

// deriveSettings applies the options that reach a scope: untagged ones, and those
// tagged with the tag its range set. A global router only reaches the scope whose
// subnet contains it; a tagged one must be in the subnet.
func deriveSettings(opts []dmOption, tag string, subnet netip.Prefix, server string) (scopeSettings, error) {
	var st scopeSettings
	byCode := map[int]DHCPOption{}
	for _, o := range opts {
		if o.tag != "" && o.tag != tag {
			continue
		}
		switch o.code {
		case 3:
			a, _ := netip.ParseAddr(o.vals[0])
			if !subnet.Contains(a) {
				if o.tag != "" {
					return st, fmt.Errorf("tagged router %s is outside %s", o.vals[0], subnet)
				}
				continue
			}
			st.router = o.vals[0]
		case 6:
			if !(len(o.vals) == 1 && o.vals[0] == server) {
				st.dns = o.vals
			}
		default:
			if _, dup := byCode[o.code]; dup {
				return st, fmt.Errorf("option %d is given twice for one scope", o.code)
			}
			byCode[o.code] = DHCPOption{Code: o.code, Type: o.typ, Value: o.vals}
		}
	}
	for _, o := range byCode {
		st.others = append(st.others, o)
	}
	sort.Slice(st.others, func(i, j int) bool { return st.others[i].Code < st.others[j].Code })
	return st, nil
}

func sameOptions(a, b []DHCPOption) bool {
	norm := func(in []DHCPOption) []DHCPOption {
		out := append([]DHCPOption(nil), in...)
		sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
		return out
	}
	return reflect.DeepEqual(norm(a), norm(b)) || (len(a) == 0 && len(b) == 0)
}

func sameStrings(a, b []string) bool {
	return (len(a) == 0 && len(b) == 0) || reflect.DeepEqual(a, b)
}

// splitRange separates a leading set:tag from a dhcp-range's fields.
func splitRange(value string) (tag string, fields []string, err error) {
	fields = strings.Split(value, ",")
	if len(fields) > 0 && strings.HasPrefix(fields[0], "set:") {
		tag, fields = strings.TrimPrefix(fields[0], "set:"), fields[1:]
	}
	for _, f := range fields {
		if strings.Contains(f, ":") && !strings.Contains(f, "::") && (strings.HasPrefix(f, "tag:") || strings.HasPrefix(f, "interface:") || strings.HasPrefix(f, "vendor:")) {
			return "", nil, fmt.Errorf("range %q matches on %s, which a scope cannot express", value, f)
		}
	}
	if len(fields) != 4 {
		return "", nil, fmt.Errorf("use [set:tag,]start,end,netmask/prefix,lifetime; static, mode and match-tag ranges need manual conversion")
	}
	return tag, fields, nil
}
