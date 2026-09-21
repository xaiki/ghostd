//go:build dhcp && !dnsmasq

package rpc

import (
	"context"

	pb "github.com/xaiki/ghostd/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) handoverAction(context.Context, *pb.RegistryDocument) (*pb.RegistryResponse, error) {
	return nil, status.Error(codes.Unimplemented, "dnsmasq takeover is not built into this daemon (build tag dnsmasq)")
}

// handoverPending: the handover journal is the dnsmasq feature's (see
// internal/addressbook's own build tag), so a daemon without it has nothing
// pending for `applyDHCP` to trip over. The dhcp-only build keeps the guard in
// dhcp.go; it just never fires here.
func (s *Server) handoverPending() (bool, error) { return false, nil }
