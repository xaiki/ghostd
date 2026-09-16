package nft

import "encoding/json"

// DesiredState is the JSON shape Nornir sends in ApplyRequest.desired_state_json
// — a direct, unchanged port of the firewall.base.zones/firewall.ingress
// schema (docs/ops/firewall.md, pre-Phase-4) onto this daemon's own
// renderer. Nornir still owns the schema and its validation rules (a zone
// literally named "trusted" reusing the full-accept convention, at least
// one zone must declare ssh, an egress zone named in `forward` must exist
// under `Zones`, etc.) — this struct is just the wire shape those already-
// validated values travel in.
type DesiredState struct {
	Zones   map[string]Zone `json:"zones"`
	Ingress *Ingress        `json:"ingress,omitempty"`
}

type Zone struct {
	Interfaces []string   `json:"interfaces"`
	SSH        *SSHRule   `json:"ssh,omitempty"`
	NFS        *NFSRule   `json:"nfs,omitempty"`
	Services   []string   `json:"services,omitempty"`
	Ports      []PortRule `json:"ports,omitempty"`
	Target     string     `json:"target,omitempty"`  // "DROP" (default) or "ACCEPT"
	Forward    []string   `json:"forward,omitempty"` // egress zone names
	Masquerade bool       `json:"masquerade,omitempty"`
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
	if err := json.Unmarshal([]byte(raw), &ds); err != nil {
		return DesiredState{}, err
	}
	return ds, nil
}
