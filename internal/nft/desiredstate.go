package nft

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// DesiredState is the JSON shape a client sends in
// ApplyRequest.desired_state_json: the zone and ingress schema this daemon
// renders. The client still owns that schema and the policy decisions behind
// it (a zone literally named "trusted" reusing the full-accept convention, at
// least one zone must declare ssh, an egress zone named in `forward` must
// exist under Zones, and so on) — this struct is just the wire shape those
// already-resolved values travel in. See docs/firewall.md.
type DesiredState struct {
	RedirectOnly bool            `json:"redirect_only,omitempty"`
	Zones        map[string]Zone `json:"zones"`
	Ingress      *Ingress        `json:"ingress,omitempty"`
	Output       *OutputPolicy   `json:"output,omitempty"`
	// AllowDNATForward accepts forwarded flows that another table DNATed (`ct
	// status dnat`). The mdns NAT installs its own DNAT table; without this the
	// default-drop forward policy here would discard the translated flows. Only
	// connections that a DNAT rule actually rewrote are admitted.
	AllowDNATForward bool `json:"allow_dnat_forward,omitempty"`
}

type Zone struct {
	Interfaces []string       `json:"interfaces"`
	SSH        *SSHRule       `json:"ssh,omitempty"`
	NFS        *NFSRule       `json:"nfs,omitempty"`
	Services   []string       `json:"services,omitempty"`
	Ports      []PortRule     `json:"ports,omitempty"`
	Target     string         `json:"target,omitempty"`  // "DROP" (default) or "ACCEPT"
	Forward    []string       `json:"forward,omitempty"` // egress zone names
	Masquerade bool           `json:"masquerade,omitempty"`
	Redirects  []RedirectRule `json:"redirects,omitempty"`
}

// RedirectRule publishes one rootless listener through a privileged host port.
type RedirectRule struct {
	Port   int    `json:"port"`
	ToPort int    `json:"to_port"`
	Proto  string `json:"proto"`
}

type SSHRule struct {
	Port int `json:"port"`
}

type NFSRule struct {
	Exports []string `json:"exports"`
}

type PortRule struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"` // "tcp" or "udp"
}

type Ingress struct {
	Interfaces []string `json:"interfaces"`
	HTTPPort   int      `json:"http_port"`
}

func ParseDesiredState(raw string) (DesiredState, error) {
	var ds DesiredState
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ds); err != nil {
		return DesiredState{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return DesiredState{}, fmt.Errorf("nft: trailing JSON data")
	}
	return ds, nil
}

// OutputPolicy is opt-in; absent preserves the historical unfiltered output path.
type OutputPolicy struct {
	Policy             string       `json:"policy"`
	EstablishedRelated bool         `json:"established_related"`
	Loopback           bool         `json:"loopback"`
	Rules              []OutputRule `json:"rules"`
}

type OutputRule struct {
	Proto       string `json:"proto"`
	Port        int    `json:"port"`
	Family      string `json:"family,omitempty"` // empty means both; ip or ip6 narrows it
	Interface   string `json:"interface,omitempty"`
	Destination string `json:"destination,omitempty"` // address or CIDR
}
