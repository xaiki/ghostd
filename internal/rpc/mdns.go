//go:build mdns

package rpc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xaiki/ghostd/internal/mdns"
	pb "github.com/xaiki/ghostd/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mdns-v2 is the directed relay and translation domain. mdns-v1 described one
// LAN and one container bridge per rule with fixed directions; v2 rules are
// per-direction, so the version moved rather than a v1 document being read as a
// different topology.
const domainMDNS = "mdns-v2"

// mdnsState is the mdns feature's part of Server.
type mdnsState struct {
	// MDNS advertises the mdns-v2 record set; nil disables the domain.
	MDNS *mdns.Service
}

func init() {
	registerDomain(domainMDNS, domainImpl{
		configKey: mdns.ConfigFile,
		apply:     (*Server).applyMDNS,
		restore:   (*Server).restoreMDNS,
	})
	registerStateExtender(func(s *Server, out *pb.State) error {
		if s.MDNS == nil {
			return nil
		}
		raw, err := json.Marshal(s.MDNS.Config())
		if err != nil {
			return err
		}
		out.MdnsConfigJson = string(raw)
		return nil
	})
}

// applyMDNS moves the advertised record set behind the ordinary lease: a bad
// record set, a bound port or a name another host already owns leaves the old
// set running, and an unconfirmed change reverts.
func (s *Server) applyMDNS(ctx context.Context, req *pb.ApplyRequest) (*pb.ApplyResponse, error) {
	if s.MDNS == nil {
		return nil, status.Error(codes.Unimplemented, "mDNS advertisement unavailable")
	}
	desired, err := mdns.ParseConfig([]byte(req.GetDesiredStateJson()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err = s.recoverExpired(ctx, domainMDNS); err != nil {
		return nil, err
	}
	snapshot, err := json.Marshal(s.MDNS.Config())
	if err != nil {
		return nil, err
	}
	lease, err := s.begin(ctx, req, snapshot)
	if err != nil {
		return nil, err
	}
	if err = s.MDNS.Apply(desired); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "mDNS apply failed; configuration rollback remains armed: %v", err)
	}
	if err = s.store.Save(mdns.ConfigFile, []byte(req.GetDesiredStateJson())); err != nil {
		return nil, status.Errorf(codes.Internal, "%v (rollback stays armed)", err)
	}
	return s.finishApply(ctx, domainMDNS, lease)
}

func (s *Server) restoreMDNS(raw []byte) error {
	if s.MDNS == nil {
		return fmt.Errorf("mDNS service unavailable")
	}
	cfg, err := mdns.ParseConfig(raw)
	if err != nil {
		return err
	}
	if err = s.MDNS.Apply(cfg); err != nil {
		return err
	}
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	return s.store.Save(mdns.ConfigFile, raw)
}
