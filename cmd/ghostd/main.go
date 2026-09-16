// smarthome-ghostd: one rootful daemon per host, owning firewalling
// (nftables), netconfig, and ingress port mapping, authenticated over the
// tailnet rather than by Unix login. See README.md.
//
// This binary has two modes:
//
//   - normal (no flags): boot-restores the last-confirmed state
//     synchronously, then serves the GetState/Apply/Confirm RPC on a
//     tailnet-only listener.
//   - `--revert-lease=<id>`: the dead-man's-switch's own command
//     (internal/state.Leases arms `systemd-run … -- ghostd --revert-lease=…`)
//     — restores the pre-apply snapshot and exits, independent of
//     whether the main daemon process is even still alive.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"

	"smarthome/ghostd/internal/auth"
	"smarthome/ghostd/internal/netconfig"
	"smarthome/ghostd/internal/nft"
	"smarthome/ghostd/internal/rpc"
	"smarthome/ghostd/internal/sdnotify"
	"smarthome/ghostd/internal/state"
	pb "smarthome/ghostd/proto"

	tsclient "tailscale.com/client/local"
)

const (
	defaultStoreDir       = "/var/lib/smarthome-ghostd/last-good"
	defaultPort           = 7443
	defaultDeployTag      = "tag:stack-deployer"
	defaultTailscaleIface = "tailscale0" // Linux's own convention; see the --tailscale-interface flag
	watchdogFraction      = 3            // pet the watchdog at 1/3 of WatchdogSec's interval
)

func main() {
	renderFirewall := flag.Bool("render-firewall", false, "render desired firewall JSON from stdin without touching the host")
	revertLease := flag.String("revert-lease", "", "restore the pre-apply snapshot and exit (the dead-man's-switch's own command; not for interactive use)")
	revertDomain := flag.String("revert-domain", "", "which domain --revert-lease is for (\"firewall\" or \"netconfig\") — set by Leases.Arm itself, not for interactive use")
	storeDir := flag.String("store-dir", defaultStoreDir, "where last-confirmed state is persisted")
	port := flag.Int("port", defaultPort, "tailnet-only listen port")
	deployerTag := flag.String("deployer-tag", defaultDeployTag, "the tailnet ACL tag allowed to call Apply/Confirm")
	tailscaleIface := flag.String("tailscale-interface", defaultTailscaleIface,
		"the interface name Apply's reachability guard always keeps open to this daemon's own port (nft.ReachabilityGuard)")
	watchdogSec := flag.Int("watchdog-sec", 0, "systemd WatchdogSec= value, in seconds (0 disables watchdog pinging)")
	flag.Parse()
	if *renderFirewall {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		desired, err := nft.ParseDesiredState(string(raw))
		if err != nil {
			log.Fatal(err)
		}
		script, err := nft.Render(desired, nft.ReachabilityGuard{TailscaleInterface: *tailscaleIface, Port: *port})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(script)
		return
	}

	store, err := state.NewStore(*storeDir)
	if err != nil {
		log.Fatalf("ghostd: %v", err)
	}

	if *revertLease != "" {
		if err := runRevert(store, *revertLease, *revertDomain); err != nil {
			log.Fatalf("ghostd: revert lease %s: %v", *revertLease, err)
		}
		return
	}

	if err := runDaemon(store, *port, *deployerTag, *tailscaleIface, *watchdogSec); err != nil {
		log.Fatalf("ghostd: %v", err)
	}
}

// runRevert is the dead-man's-switch's own command — see the package doc
// and internal/state.Leases.Arm. It must not depend on the main daemon
// process (it is a fresh, independent invocation of this same binary), and
// so it cannot know which domain fired except from its own flags: domain
// travels via --revert-domain, set by Leases.Arm at the moment it knows it
// (see that function's own doc on why this cannot be any kind of shared
// in-memory state instead).
// recoverDomain runs under the process-shared store lock. Timers consult the
// durable lease, so late callbacks cannot undo a newer or confirmed apply.
func recoverDomain(store *state.Store, domain, leaseID string) error {
	key := rpc.NftRuleset
	if domain == "netconfig" {
		key = rpc.NetconfigState
	} else if domain != "firewall" {
		return fmt.Errorf("unknown domain %q", domain)
	}
	d, err := store.Domain(domain, key)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if d.Pending != nil && (leaseID == "" || d.Pending.ID == leaseID) {
		if domain == "firewall" {
			err = nft.Restore(ctx, nft.ExecRunner{}, d.Pending.Snapshot)
		} else {
			err = netconfig.Rollback(ctx, netconfig.ExecRunner{}, d.Pending.Snapshot)
		}
		if err != nil {
			return err
		}
		d.Pending = nil
		return store.SaveDomain(domain, d)
	}
	if leaseID != "" {
		return nil
	}
	if domain == "firewall" {
		return nft.Restore(ctx, nft.ExecRunner{}, d.Confirmed)
	}
	return netconfig.Restore(ctx, netconfig.ExecRunner{}, d.Confirmed)
}

func runRevert(store *state.Store, leaseID, domain string) error {
	unlock, err := store.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	return recoverDomain(store, domain, leaseID)
}

func runDaemon(store *state.Store, port int, deployerTag string, tailscaleIface string, watchdogSec int) error {
	ctx := context.Background()

	unlock, err := store.Lock()
	if err != nil {
		return err
	}
	for _, domain := range []string{"firewall", "netconfig"} {
		if err := recoverDomain(store, domain, ""); err != nil {
			unlock()
			return fmt.Errorf("boot restore %s: %w", domain, err)
		}
	}
	unlock()

	tsLocal := &tsclient.Client{}
	listenAddr, err := tailnetListenAddress(ctx, tsLocal, port)
	if err != nil {
		return fmt.Errorf("resolve tailnet listen address: %w", err)
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listenAddr, err)
	}
	log.Printf("ghostd: listening on %s (tailnet-only)", listenAddr)

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own binary path (needed to arm the dead-man's-switch): %w", err)
	}
	leases := state.NewLeases(exePath, state.ExecRunner{})
	authenticator := auth.NewAuthenticator(tsLocal, deployerTag)
	guard := nft.ReachabilityGuard{TailscaleInterface: tailscaleIface, Port: port}
	server := rpc.NewServer(authenticator, store, leases, nft.ExecRunner{}, netconfig.ExecRunner{}, guard)

	grpcServer := grpc.NewServer()
	pb.RegisterHostStateServer(grpcServer, server)

	if watchdogSec > 0 {
		go petWatchdog(time.Duration(watchdogSec) * time.Second / watchdogFraction)
	}
	if err := sdnotify.Ready(); err != nil {
		log.Printf("ghostd: sd_notify READY failed (non-fatal): %v", err)
	}

	return grpcServer.Serve(listener)
}

func petWatchdog(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if err := sdnotify.Watchdog(); err != nil {
			log.Printf("ghostd: sd_notify WATCHDOG failed (non-fatal): %v", err)
		}
	}
}

// tailnetListenAddress asks the host's own tailscaled for this node's
// tailnet address — never 0.0.0.0, never a LAN/mgmt interface. Binding to
// a specific address (not just trusting firewall policy to keep LAN
// traffic out) is the primary control: even a misconfigured or
// not-yet-converged firewall domain cannot expose this socket off-tailnet.
func tailnetListenAddress(ctx context.Context, client *tsclient.Client, port int) (string, error) {
	status, err := client.Status(ctx)
	if err != nil {
		return "", fmt.Errorf("tailscaled status: %w (is tailscaled running and joined?)", err)
	}
	if status.Self == nil || len(status.Self.TailscaleIPs) == 0 {
		return "", fmt.Errorf("this host has no tailnet address yet (not joined?)")
	}
	ip := status.Self.TailscaleIPs[0]
	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil
}
