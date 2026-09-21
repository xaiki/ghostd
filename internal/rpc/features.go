package rpc

import (
	"context"
	"sort"

	"github.com/xaiki/ghostd/internal/state"
	pb "github.com/xaiki/ghostd/proto"
)

// Optional features (build tags dhcp, dnsmasq, mdns) plug into the core RPC
// surface through these tables from init functions in their own files, so a
// daemon built without them has neither the code nor the domains.

// domainImpl is one optional Apply/Confirm domain riding the ordinary lease.
type domainImpl struct {
	// configKey is the legacy blob name for the domain's confirmed state.
	configKey string
	apply     func(*Server, context.Context, *pb.ApplyRequest) (*pb.ApplyResponse, error)
	// restore makes the running feature match a snapshot after a rollback.
	restore func(*Server, []byte) error
}

var extraDomains = map[string]domainImpl{}

func registerDomain(name string, d domainImpl) {
	extraDomains[name] = d
	state.RegisterDomain(name)
}

// extraDomainNames lists the optional domains in a stable order.
func extraDomainNames() []string {
	names := make([]string, 0, len(extraDomains))
	for n := range extraDomains {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

var stateExtenders []func(*Server, *pb.State) error

func registerStateExtender(f func(*Server, *pb.State) error) {
	stateExtenders = append(stateExtenders, f)
}
