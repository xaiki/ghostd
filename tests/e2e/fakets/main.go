// Command fakets is a minimal stand-in for tailscaled's LocalAPI, for the
// end-to-end lab only. It answers /status with a tailnet address and /whois
// with a deployer-tagged node, so the real ghostd binary can boot, bind and
// authenticate callers inside a container that has no tailnet.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

func main() {
	sock := flag.String("socket", "/var/run/tailscale/tailscaled.sock", "LocalAPI socket")
	ip := flag.String("ip", "127.0.0.1", "tailnet address reported for this node")
	tag := flag.String("tag", "tag:stack-deployer", "tag given to every caller; empty makes callers plain peers")
	peers := flag.String("peers", "/run/tailscale/peers.json", "optional JSON object of node-key -> PeerStatus to report as tailnet peers")
	capDeploy := flag.Bool("cap-deploy", false, "grant every caller the ghostd.local/cap/deploy capability, as a tailnet grant would")
	user := flag.String("user", "operator@example.com", "login reported for every caller")
	flag.Parse()
	_ = os.Remove(*sock)
	l, err := net.Listen("unix", *sock)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/localapi/v0/status", func(w http.ResponseWriter, r *http.Request) {
		status := map[string]any{
			"Version": "1.0-fake", "BackendState": "Running",
			"Self": map[string]any{"ID": "self", "DNSName": "ghostd-e2e.example.ts.net.", "TailscaleIPs": []string{*ip}, "Online": true},
		}
		if raw, err := os.ReadFile(*peers); err == nil {
			var p map[string]any
			if json.Unmarshal(raw, &p) == nil {
				status["Peer"] = p
			}
		}
		json.NewEncoder(w).Encode(status)
	})
	mux.HandleFunc("/localapi/v0/whois", func(w http.ResponseWriter, r *http.Request) {
		addr := strings.TrimSpace(r.URL.Query().Get("addr"))
		if addr == "" {
			http.Error(w, "no addr", http.StatusBadRequest)
			return
		}
		node := map[string]any{"ID": 1, "StableID": "node-e2e", "Name": "operator.example.ts.net.", "Addresses": []string{"100.64.0.2/32"}}
		if *tag != "" {
			node["Tags"] = []string{*tag}
		}
		caps := map[string]any{}
		if *capDeploy {
			caps["ghostd.local/cap/deploy"] = []any{map[string]any{"deploy": true}}
		}
		json.NewEncoder(w).Encode(map[string]any{"Node": node, "UserProfile": map[string]any{"ID": 1, "LoginName": *user}, "CapMap": caps})
	})
	log.Fatal(http.Serve(l, mux))
}
