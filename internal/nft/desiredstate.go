package nft

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// DesiredState is the JSON shape Nornir sends in ApplyRequest.desired_state_json
// — a direct, unchanged port of the firewall.base.zones/firewall.ingress
// schema (docs/ops/firewall.md, pre-Phase-4) onto this daemon's own
// renderer. Nornir still owns the schema and its validation rules (a zone
// literally named "trusted" reusing the full-accept convention, at least
// one zone must declare ssh, an egress zone named in `forward` must exist
// under `Zones`, etc.) — this struct is just the wire shape those already-
// validated values travel in.
type DesiredState struct {
	RedirectOnly bool            `json:"redirect_only,omitempty"`
	Zones        map[string]Zone `json:"zones"`
	Ingress      *Ingress        `json:"ingress,omitempty"`
	Output       *OutputPolicy   `json:"output,omitempty"`
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
