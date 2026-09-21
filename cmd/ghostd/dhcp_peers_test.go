//go:build dhcp

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/xaiki/ghostd/internal/addressbook"
	"github.com/xaiki/ghostd/internal/overlay"
)

type peerProvider struct {
	peers []overlay.Peer
	err   error
}

func (peerProvider) Name() string                                           { return "fake" }
func (peerProvider) ListenAddress(context.Context, int) (string, error)     { return "", nil }
func (peerProvider) Whois(context.Context, string) (*overlay.Caller, error) { return nil, nil }
func (p peerProvider) Peers(context.Context) ([]overlay.Peer, error)        { return p.peers, p.err }

func TestOverlayPeersKeepsOnlyPrivateEndpoints(t *testing.T) {
	got, err := overlayPeers(context.Background(), peerProvider{peers: []overlay.Peer{{
		ID: "n1", DNSName: "nas.ts.net.", HostName: "nas", Online: true, Addresses: []string{"100.64.0.9"},
		Endpoints: []string{"192.168.1.5:41641", "203.0.113.1:41641", "[2001:db8::1]:1", "10.1.2.3:9"},
	}}})
	if err != nil || len(got) != 1 {
		t.Fatal(got, err)
	}
	want := addressbook.PrivateEndpoints("192.168.1.5:41641", "10.1.2.3:9")
	if len(got[0].LANAddrs) != 2 || got[0].LANAddrs[0] != want[0] || got[0].LANAddrs[1] != want[1] || got[0].ID != "n1" || len(got[0].Addresses) != 1 {
		t.Fatal("public endpoints must never become LAN evidence:", got[0])
	}
	if _, err := overlayPeers(context.Background(), peerProvider{err: errors.New("down")}); err == nil {
		t.Fatal("a provider failure must surface")
	}
	if _, err := overlayPeers(context.Background(), peerProvider{err: overlay.ErrUnsupported}); !errors.Is(err, overlay.ErrUnsupported) {
		t.Fatal(err)
	}
}
