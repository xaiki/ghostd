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

func (s *Server) handoverPending() (bool, error) { return false, nil }
