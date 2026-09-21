//go:build tailscale || headscale

package localapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xaiki/ghostd/internal/overlay"
)

// fakeDaemon answers the local API on a unix socket, as tailscaled would.
func fakeDaemon(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ts")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s") // unix socket paths are short
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/localapi/v0/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"Self": map[string]any{"TailscaleIPs": []string{"100.64.0.7"}},
			"Peer": map[string]any{"nodekey:" + strings.Repeat("ab", 32): map[string]any{
				"ID": "n1", "HostName": "nas", "DNSName": "nas.example.ts.net.", "TailscaleIPs": []string{"100.64.0.9"},
				"CurAddr": "192.0.2.5:41641", "Addrs": []string{"203.0.113.1:1"}, "Online": true}},
		})
	})
	mux.HandleFunc("/localapi/v0/whois", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("addr") == "100.64.0.99:1" {
			http.Error(w, "no such peer", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"Node":        map[string]any{"StableID": "node-1", "Name": "op.example.ts.net.", "Tags": []string{"tag:stack-deployer"}, "Addresses": []string{"100.64.0.2/32"}},
			"UserProfile": map[string]any{"LoginName": "op@example.com"},
			"CapMap":      map[string]any{"ghostd.local/cap/deploy": []any{map[string]any{"deploy": true}}},
		})
	})
	go http.Serve(l, mux)
	t.Cleanup(func() { l.Close() })
	return sock
}

func TestProvidersReadTheSameLocalAPIButTrustDifferentThings(t *testing.T) {
	sock := fakeDaemon(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name      string
		trustCaps bool
	}{{"tailscale", true}, {"headscale", false}} {
		t.Run(tc.name, func(t *testing.T) {
			p := New(tc.name, overlay.Options{Socket: sock}, tc.trustCaps)
			if p.Name() != tc.name {
				t.Fatal(p.Name())
			}
			addr, err := p.ListenAddress(ctx, 7443)
			if err != nil || addr != "100.64.0.7:7443" {
				t.Fatal("listen address must be the overlay's own:", addr, err)
			}
			c, err := p.Whois(ctx, "100.64.0.2:5000")
			if err != nil || c.Login != "op@example.com" || c.NodeID != "node-1" || len(c.Tags) != 1 || c.Tags[0] != "tag:stack-deployer" || len(c.Addresses) != 1 || c.Addresses[0] != "100.64.0.2" {
				t.Fatal(c, err)
			}
			if hasCap := len(c.Capabilities["ghostd.local/cap/deploy"]) == 1; hasCap != tc.trustCaps {
				t.Fatalf("capabilities trusted=%v but present=%v: a control plane without grants must not have them believed", tc.trustCaps, hasCap)
			}
			if _, err = p.Whois(ctx, "100.64.0.99:1"); err == nil {
				t.Fatal("an unknown address resolved")
			}
			peers, err := p.Peers(ctx)
			if err != nil || len(peers) != 1 || peers[0].HostName != "nas" || len(peers[0].Endpoints) != 2 || peers[0].Endpoints[0] != "192.0.2.5:41641" {
				t.Fatal(peers, err)
			}
		})
	}
}

func TestNoDaemonIsAnErrorNotAnAddress(t *testing.T) {
	p := New("tailscale", overlay.Options{Socket: "/tmp/ghostd-absent.sock"}, true)
	if a, err := p.ListenAddress(context.Background(), 1); err == nil {
		t.Fatal("bound something without a daemon:", a)
	}
}
