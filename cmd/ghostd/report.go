package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/xaiki/ghostd/internal/addressbook"
	pb "github.com/xaiki/ghostd/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Identity is resolved by the receiver using tailscaled WhoIs. The sender can
// describe interfaces, never choose the tailnet node it claims to represent.
func reportHost(ctx context.Context, authority string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	report := struct {
		Interfaces []addressbook.InterfaceReport `json:"interfaces"`
	}{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || len(iface.HardwareAddr) != 6 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		item := addressbook.InterfaceReport{MAC: iface.HardwareAddr.String()}
		for _, a := range addresses {
			p, e := netip.ParsePrefix(a.String())
			if e == nil && !p.Addr().IsLoopback() && !p.Addr().IsLinkLocalUnicast() {
				item.Addresses = append(item.Addresses, p.Addr().String())
			}
		}
		if len(item.Addresses) > 0 {
			report.Interfaces = append(report.Interfaces, item)
		}
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	// Restrict transport to the encrypted overlay; never send a report to LAN or
	// public DNS answers where plaintext gRPC would lack the tailnet protection.
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		host, port = authority, "7443"
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	var target string
	for _, ip := range addresses {
		if netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(ip) {
			target = net.JoinHostPort(ip.String(), port)
			break
		}
	}
	if target == "" {
		return "", fmt.Errorf("identity authority must resolve to a tailnet address")
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	reply, err := pb.NewHostStateClient(conn).ReportHost(ctx, &pb.RegistryDocument{Json: string(raw)})
	if err != nil {
		return "", err
	}
	return reply.GetJson(), nil
}
func runReports(ctx context.Context, authority string) {
	for {
		attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
		_, err := reportHost(attempt, authority)
		cancel()
		if err != nil {
			log.Printf("ghostd identity report: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}
