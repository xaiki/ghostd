//go:build dhcp

// Package addressbook owns scoped address allocations and device attribution.
// Configuration can be reverted independently of the durable allocation ledger.
package addressbook

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const ConfigFile = "dhcp-config.json"

var labelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var interfacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

type Config struct {
	Scopes  []Scope        `json:"scopes"`
	Devices []DeviceConfig `json:"devices,omitempty"`
	// TFTP serves a read-only tree on every enabled IPv4 scope's server address.
	TFTP *TFTPConfig `json:"tftp,omitempty"`
}

// BootConfig is the network-boot hand-off (PXE) a scope gives its clients:
// siaddr, the boot file name, and option 66.
// DHCPOption is one extra DHCPv4 option: Type "ips" (IPv4 addresses), "text",
// "u8", "u16" or "u32" (one number).
type DHCPOption struct {
	Code  int      `json:"code"`
	Type  string   `json:"type"`
	Value []string `json:"value"`
}

type BootConfig struct {
	// Always sends the boot fields to every client. By default, like dnsmasq, they
	// go only to clients that ask: a parameter request for option 66 or 67, a
	// PXEClient vendor class, or a plain BOOTP request.
	Always bool   `json:"always,omitempty"`
	File   string `json:"file"`
	// NextServer defaults to the scope's own server address, where ghostd's TFTP
	// (or another server) is expected.
	NextServer string `json:"next_server,omitempty"`
}
type TFTPConfig struct {
	Root string `json:"root"`
	// Interfaces limits TFTP to scopes on these interfaces; empty means every
	// enabled IPv4 scope.
	Interfaces []string `json:"interfaces,omitempty"`
}
type Scope struct {
	ID               string        `json:"id"`
	Interface        string        `json:"interface"`
	Subnet           string        `json:"subnet"`
	Server           string        `json:"server"`
	Start            string        `json:"start"`
	End              string        `json:"end"`
	Router           string        `json:"router"`
	Zone             string        `json:"zone"`
	LeaseSeconds     int           `json:"lease_seconds"`
	Enabled          bool          `json:"enabled"`
	Reservations     []Reservation `json:"reservations,omitempty"`
	PreferredSeconds int           `json:"preferred_seconds,omitempty"`
	Relay            *RelayConfig  `json:"relay,omitempty"`
	RA               *RAConfig     `json:"ra,omitempty"`
	Boot             *BootConfig   `json:"boot,omitempty"`
	// DNSServers replaces the advertised DNS server (option 6) when the scope
	// should hand out other resolvers than itself; empty means the scope's own
	// server, as dnsmasq does by default.
	DNSServers []string `json:"dns_servers,omitempty"`
	// Options are extra DHCPv4 options handed to every client of the scope.
	Options []DHCPOption `json:"options,omitempty"`
	// PD delegates prefixes (IA_PD) from a pool to routers on this IPv6 link.
	PD *PDConfig `json:"pd,omitempty"`
}

// PDConfig is a DHCPv6 prefix-delegation pool. Every delegated prefix has the
// same Length; Route installs a kernel route to each one via the requesting
// router's link-local address, and removes it when the delegation ends.
type PDConfig struct {
	Prefix string `json:"prefix"`
	Length int    `json:"length"`
	Route  bool   `json:"route,omitempty"`
}
type Reservation struct {
	Client  string `json:"client"` // mac:aa:bb:... or id:<option-61 hex>
	Address string `json:"address"`
	Device  string `json:"device"`
}
type DeviceConfig struct {
	Aliases []string `json:"aliases,omitempty"`
	NodeIDs []string `json:"tailnet_node_ids,omitempty"`
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	NodeID  string   `json:"tailnet_node_id,omitempty"`
}

func ParseConfig(raw []byte) (Config, error) {
	var c Config
	if len(raw) == 0 {
		raw = []byte(`{"scopes":[]}`)
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, fmt.Errorf("trailing config data")
	}
	return c, c.Validate()
}

type RelayConfig struct {
	Peer string `json:"peer"`
	Link string `json:"link"`
}
type RAConfig struct {
	SLAAC          bool `json:"slaac"`
	RouterLifetime int  `json:"router_lifetime"`
	Interval       int  `json:"interval"`
}

func (s Scope) Is6() bool { p, e := netip.ParsePrefix(s.Subnet); return e == nil && p.Addr().Is6() }
func (s Scope) socketKey() string {
	family := "4"
	if s.Is6() {
		family = "6"
	}
	return family + "/" + s.Interface
}
func (c Config) Validate() error {
	devices, nodes, names := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, d := range c.Devices {
		if !labelPattern.MatchString(d.ID) || !labelPattern.MatchString(d.Name) || d.Name == "ns" || devices[d.ID] || names[d.Name] {
			return fmt.Errorf("invalid/duplicate device ID or name %q", d.ID)
		}
		devices[d.ID], names[d.Name] = true, true
		for _, alias := range d.Aliases {
			if !labelPattern.MatchString(alias) || alias == "ns" || names[alias] {
				return fmt.Errorf("invalid/duplicate DNS alias %q", alias)
			}
			names[alias] = true
		}
		for _, nodeID := range append(append([]string(nil), d.NodeIDs...), d.NodeID) {
			if nodeID == "" {
				continue
			}
			if nodes[nodeID] {
				return fmt.Errorf("duplicate tailnet node %q", d.NodeID)
			}
			nodes[nodeID] = true
		}
	}
	if c.TFTP != nil {
		for _, i := range c.TFTP.Interfaces {
			if !interfacePattern.MatchString(i) {
				return fmt.Errorf("tftp: bad interface %q", i)
			}
		}
	}
	if c.TFTP != nil && (!filepath.IsAbs(c.TFTP.Root) || filepath.Clean(c.TFTP.Root) != c.TFTP.Root || len(c.TFTP.Root) > 4096 || c.TFTP.Root == "/") {
		return fmt.Errorf("tftp root must be an absolute, clean directory other than /")
	}
	pdPools := map[netip.Prefix]string{}
	ids, selectors, zones := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var prefixes []netip.Prefix
	for _, s := range c.Scopes {
		if !labelPattern.MatchString(s.ID) || ids[s.ID] || !interfacePattern.MatchString(s.Interface) {
			return fmt.Errorf("invalid/duplicate scope or interface %q", s.ID)
		}
		ids[s.ID] = true
		p, e := netip.ParsePrefix(s.Subnet)
		if e != nil || p != p.Masked() || p.Addr().Is4In6() || p.Addr().IsMulticast() || (p.Addr().Is4() && p.Bits() > 30) || (p.Addr().Is6() && p.Bits() > 126) {
			return fmt.Errorf("scope %s requires a canonical subnet with host addresses", s.ID)
		}
		for _, other := range prefixes {
			if p.Overlaps(other) {
				return fmt.Errorf("overlapping scopes on one authority are not supported")
			}
		}
		prefixes = append(prefixes, p)
		valid := func(v string) bool {
			a, e := netip.ParseAddr(v)
			return e == nil && p.Contains(a) && a != p.Addr() && (!a.Is4() || a != lastAddr(p))
		}
		server, e := netip.ParseAddr(s.Server)
		if e != nil || server.IsUnspecified() || server.IsMulticast() || server.Is4() != p.Addr().Is4() || server.Zone() != "" {
			return fmt.Errorf("invalid server address in %s", s.ID)
		}
		selector := s.socketKey() + "/direct"
		if s.Relay != nil {
			peer, e := netip.ParseAddr(s.Relay.Peer)
			link, le := netip.ParseAddr(s.Relay.Link)
			if e != nil || le != nil || peer.IsUnspecified() || peer.IsMulticast() || peer.Is4() != server.Is4() || !p.Contains(link) || link.IsUnspecified() {
				return fmt.Errorf("invalid relay peer/link in %s", s.ID)
			}
			selector = s.socketKey() + "/" + peer.String() + "/" + link.String()
		} else if !valid(s.Server) {
			return fmt.Errorf("server must be on direct scope %s", s.ID)
		}
		if selectors[selector] {
			return fmt.Errorf("ambiguous scope selector %s", selector)
		}
		selectors[selector] = true
		if !valid(s.Start) || !valid(s.End) || (!s.Is6() && !valid(s.Router)) || netip.MustParseAddr(s.Start).Compare(netip.MustParseAddr(s.End)) > 0 {
			return fmt.Errorf("invalid addresses in scope %s", s.ID)
		}
		a, end := netip.MustParseAddr(s.Start), netip.MustParseAddr(s.End)
		for n := 0; a.Compare(end) <= 0; n++ {
			if n >= 65536 {
				return fmt.Errorf("pool limited to 65536 addresses")
			}
			a = a.Next()
		}
		if s.LeaseSeconds < 60 || s.LeaseSeconds > 604800 {
			return fmt.Errorf("lease_seconds must be 60..604800")
		}
		if s.Is6() && (s.PreferredSeconds < 1 || s.PreferredSeconds > s.LeaseSeconds) {
			return fmt.Errorf("preferred_seconds must be positive and <= lease_seconds")
		}
		if !s.Is6() && (s.PreferredSeconds != 0 || s.RA != nil) {
			return fmt.Errorf("IPv6 settings on IPv4 scope")
		}
		if s.RA != nil {
			if s.Relay != nil || p.Bits() != 64 || s.RA.Interval < 4 || s.RA.Interval > 600 || s.RA.RouterLifetime < 0 || s.RA.RouterLifetime > 9000 || (s.RA.RouterLifetime > 0 && s.RA.RouterLifetime < s.RA.Interval*3) {
				return fmt.Errorf("RA needs a direct /64, interval 4..600 and router_lifetime 0 or 3*interval..9000")
			}
		}
		if len(s.DNSServers) > 0 || len(s.Options) > 0 {
			if s.Is6() {
				return fmt.Errorf("scope %s: DNS servers and options are IPv4 settings", s.ID)
			}
			if len(s.DNSServers) > 8 || len(s.Options) > 32 {
				return fmt.Errorf("scope %s: too many DNS servers or options", s.ID)
			}
			for _, d := range s.DNSServers {
				if a, e := netip.ParseAddr(d); e != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() {
					return fmt.Errorf("scope %s: dns_servers must be unicast IPv4 addresses", s.ID)
				}
			}
			seenCodes := map[int]bool{}
			for _, o := range s.Options {
				if err := o.validate(); err != nil {
					return fmt.Errorf("scope %s: %w", s.ID, err)
				}
				if seenCodes[o.Code] {
					return fmt.Errorf("scope %s: option %d given twice", s.ID, o.Code)
				}
				seenCodes[o.Code] = true
			}
		}
		if s.PD != nil {
			if !s.Is6() {
				return fmt.Errorf("scope %s: prefix delegation needs an IPv6 scope", s.ID)
			}
			pool, e := netip.ParsePrefix(s.PD.Prefix)
			if e != nil || pool != pool.Masked() || !pool.Addr().Is6() || pool.Addr().Is4In6() {
				return fmt.Errorf("scope %s: pd prefix must be a canonical IPv6 prefix", s.ID)
			}
			if s.PD.Length <= pool.Bits() || s.PD.Length > 64 || s.PD.Length-pool.Bits() > 16 || s.PD.Length < 32 {
				return fmt.Errorf("scope %s: pd length must be 32..64, longer than the pool prefix, at most 16 bits deeper (65536 delegations)", s.ID)
			}
			if pool.Overlaps(p) {
				return fmt.Errorf("scope %s: the pd pool overlaps the scope's own subnet", s.ID)
			}
			for _, other := range prefixes[:len(prefixes)-1] {
				if pool.Overlaps(other) {
					return fmt.Errorf("scope %s: the pd pool overlaps another scope", s.ID)
				}
			}
			for prior, existing := range pdPools {
				if pool.Overlaps(prior) {
					return fmt.Errorf("scope %s: the pd pool overlaps scope %s's pool", s.ID, existing)
				}
			}
			pdPools[pool] = s.ID
		}
		if s.Boot != nil {
			if s.Is6() {
				return fmt.Errorf("network boot is IPv4 only (scope %s)", s.ID)
			}
			if s.Boot.File == "" || len(s.Boot.File) > 128 || strings.ContainsAny(s.Boot.File, "\x00\r\n") {
				return fmt.Errorf("scope %s: boot file must be 1..128 printable characters", s.ID)
			}
			if s.Boot.NextServer != "" {
				if a, e := netip.ParseAddr(s.Boot.NextServer); e != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() {
					return fmt.Errorf("scope %s: next_server must be a unicast IPv4 address", s.ID)
				}
			}
		}
		if !validZone(s.Zone) {
			return fmt.Errorf("scope %s needs a local DNS zone (not .local or .ts.net)", s.ID)
		}
		for zone := range zones {
			if strings.HasSuffix(zone, "."+s.Zone) || strings.HasSuffix(s.Zone, "."+zone) {
				return fmt.Errorf("nested authoritative zones are not supported")
			}
		}
		zones[s.Zone] = true
		clients, addresses := map[string]bool{}, map[string]bool{}
		for _, r := range s.Reservations {
			if !validClient(r.Client) || !valid(r.Address) || r.Address == s.Server || r.Address == s.Router || !devices[r.Device] || clients[r.Client] || addresses[r.Address] {
				return fmt.Errorf("invalid/duplicate reservation in %s", s.ID)
			}
			if s.Is6() != strings.HasPrefix(r.Client, "duid:") {
				return fmt.Errorf("reservation client family does not match scope")
			}
			clients[r.Client], addresses[r.Address] = true, true
		}
	}
	return nil
}
func validZone(s string) bool {
	if !strings.Contains(s, ".") || strings.HasSuffix(s, ".local") || strings.HasSuffix(s, ".ts.net") || len(s) > 200 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}
func validClient(s string) bool {
	if strings.HasPrefix(s, "duid:") {
		parts := strings.Split(strings.TrimPrefix(s, "duid:"), "/iaid:")
		if len(parts) != 2 || len(parts[1]) != 8 || len(parts[0]) < 4 || len(parts[0]) > 256 {
			return false
		}
		_, a := hex.DecodeString(parts[0])
		_, b := hex.DecodeString(parts[1])
		return a == nil && b == nil && strings.ToLower(s) == s
	}

	if strings.HasPrefix(s, "mac:") {
		mac, err := net.ParseMAC(strings.TrimPrefix(s, "mac:"))
		return err == nil && len(mac) == 6 && "mac:"+mac.String() == s
	}
	if strings.HasPrefix(s, "id:") {
		v := strings.TrimPrefix(s, "id:")
		return len(v) >= 2 && len(v) <= 510 && len(v)%2 == 0 && regexp.MustCompile(`^[0-9a-f]+$`).MatchString(v)
	}
	return false
}
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	n |= uint32(0xffffffff) >> p.Bits()
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}
func (c Config) Scope(id string) (Scope, bool) {
	for _, s := range c.Scopes {
		if s.ID == id {
			return s, true
		}
	}
	return Scope{}, false
}
func (c Config) Device(id string) (DeviceConfig, bool) {
	for _, d := range c.Devices {
		if d.ID == id {
			return d, true
		}
	}
	return DeviceConfig{}, false
}

func cloneConfig(c Config) Config {
	out := Config{Scopes: append([]Scope(nil), c.Scopes...), Devices: append([]DeviceConfig(nil), c.Devices...)}
	if c.TFTP != nil {
		x := *c.TFTP
		x.Interfaces = append([]string(nil), c.TFTP.Interfaces...)
		out.TFTP = &x
	}
	for i := range out.Devices {
		out.Devices[i].NodeIDs = append([]string(nil), c.Devices[i].NodeIDs...)
		out.Devices[i].Aliases = append([]string(nil), c.Devices[i].Aliases...)
	}
	for i := range out.Scopes {
		out.Scopes[i].Reservations = append([]Reservation(nil), c.Scopes[i].Reservations...)
		if c.Scopes[i].Relay != nil {
			x := *c.Scopes[i].Relay
			out.Scopes[i].Relay = &x
		}
		if c.Scopes[i].RA != nil {
			x := *c.Scopes[i].RA
			out.Scopes[i].RA = &x
		}
		if c.Scopes[i].Boot != nil {
			x := *c.Scopes[i].Boot
			out.Scopes[i].Boot = &x
		}
		out.Scopes[i].DNSServers = append([]string(nil), c.Scopes[i].DNSServers...)
		out.Scopes[i].Options = nil
		for _, o := range c.Scopes[i].Options {
			o.Value = append([]string(nil), o.Value...)
			out.Scopes[i].Options = append(out.Scopes[i].Options, o)
		}
		if c.Scopes[i].PD != nil {
			x := *c.Scopes[i].PD
			out.Scopes[i].PD = &x
		}
	}
	return out
}

func (d DeviceConfig) HasNode(id string) bool {
	if id == "" {
		return false
	}
	if d.NodeID == id {
		return true
	}
	for _, n := range d.NodeIDs {
		if n == id {
			return true
		}
	}
	return false
}
func (d DeviceConfig) DeclaresNodes() bool { return d.NodeID != "" || len(d.NodeIDs) > 0 }

func (d DeviceConfig) HasAlias(name string) bool {
	for _, alias := range d.Aliases {
		if alias == name {
			return true
		}
	}
	return false
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

func disabled(c Config) Config {
	c = cloneConfig(c)
	for i := range c.Scopes {
		c.Scopes[i].Enabled = false
	}
	return c
}

// reserved option codes are set by the server itself and cannot be overridden.
var reservedOptionCodes = map[int]bool{0: true, 1: true, 3: true, 6: true, 12: true, 15: true, 28: true, 50: true, 51: true, 52: true, 53: true, 54: true, 55: true, 58: true, 59: true, 60: true, 61: true, 66: true, 67: true, 119: true, 255: true}

func (o DHCPOption) validate() error {
	if o.Code < 1 || o.Code > 254 || reservedOptionCodes[o.Code] {
		return fmt.Errorf("option %d is reserved or out of range", o.Code)
	}
	if len(o.Value) == 0 || len(o.Value) > 16 {
		return fmt.Errorf("option %d needs 1..16 values", o.Code)
	}
	switch o.Type {
	case "ips":
		for _, v := range o.Value {
			if a, e := netip.ParseAddr(v); e != nil || !a.Is4() {
				return fmt.Errorf("option %d: %q is not an IPv4 address", o.Code, v)
			}
		}
	case "text":
		if len(o.Value) != 1 || len(o.Value[0]) == 0 || len(o.Value[0]) > 255 || strings.ContainsAny(o.Value[0], "\x00\r\n") {
			return fmt.Errorf("option %d: text must be one string of 1..255 printable characters", o.Code)
		}
	case "u8", "u16", "u32":
		bits := map[string]int{"u8": 8, "u16": 16, "u32": 32}[o.Type]
		n, e := strconv.ParseUint(o.Value[0], 10, bits)
		_ = n
		if len(o.Value) != 1 || e != nil {
			return fmt.Errorf("option %d: %s needs one number that fits", o.Code, o.Type)
		}
	default:
		return fmt.Errorf("option %d: unknown type %q", o.Code, o.Type)
	}
	return nil
}

// wire encodes the option's value.
func (o DHCPOption) wire() []byte {
	var out []byte
	switch o.Type {
	case "ips":
		for _, v := range o.Value {
			a := netip.MustParseAddr(v).As4()
			out = append(out, a[:]...)
		}
	case "text":
		out = []byte(o.Value[0])
	case "u8":
		n, _ := strconv.ParseUint(o.Value[0], 10, 8)
		out = []byte{byte(n)}
	case "u16":
		n, _ := strconv.ParseUint(o.Value[0], 10, 16)
		out = []byte{byte(n >> 8), byte(n)}
	case "u32":
		n, _ := strconv.ParseUint(o.Value[0], 10, 32)
		out = []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return out
}
