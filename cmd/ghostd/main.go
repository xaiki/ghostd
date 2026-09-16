// smarthome-ghostd: one rootful daemon per host, owning firewalling
// (nftables), netconfig, and ingress port mapping, authenticated over the
// tailnet rather than by Unix login. See FIREWALL.md at the repo root.
//
// This binary has two modes:
//
//   - normal (no flags): boot-restores the last-confirmed state
//     synchronously, then serves the GetState/Apply/Confirm RPC on a
//     tailnet-only listener.
//   - `--revert-lease=<id>`: the dead-man's-switch's own command
//     (internal/state.Leases arms `systemd-run … -- ghostd --revert-lease=…`)
//     — reverts to the last-confirmed state and exits, independent of
//     whether the main daemon process is even still alive.
package main

import (
	"context"
	"flag"
	"fmt"
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
	revertLease := flag.String("revert-lease", "", "revert to last-confirmed state and exit (the dead-man's-switch's own command; not for interactive use)")
	revertDomain := flag.String("revert-domain", "", "which domain --revert-lease is for (\"firewall\" or \"netconfig\") — set by Leases.Arm itself, not for interactive use")
	storeDir := flag.String("store-dir", defaultStoreDir, "where last-confirmed state is persisted")
	port := flag.Int("port", defaultPort, "tailnet-only listen port")
	deployerTag := flag.String("deployer-tag", defaultDeployTag, "the tailnet ACL tag allowed to call Apply/Confirm")
	tailscaleIface := flag.String("tailscale-interface", defaultTailscaleIface,
		"the interface name Apply's reachability guard always keeps open to this daemon's own port (nft.ReachabilityGuard)")
	watchdogSec := flag.Int("watchdog-sec", 0, "systemd WatchdogSec= value, in seconds (0 disables watchdog pinging)")
	flag.Parse()

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
func runRevert(store *state.Store, leaseID, domain string) error {
	ctx := context.Background()
	log.Printf("ghostd: dead-man's-switch fired for lease %s (%s) — reverting to last-confirmed state", leaseID, domain)
	switch domain {
	case "firewall":
		ruleset, err := store.Load(rpc.NftRuleset)
		if err != nil {
			return err
		}
		return nft.Restore(ctx, nft.ExecRunner{}, ruleset)
	case "netconfig":
		blob, err := store.Load(rpc.NetconfigState)
		if err != nil {
			return err
		}
		return netconfig.Restore(ctx, netconfig.ExecRunner{}, blob)
	default:
		return fmt.Errorf("unrecognized --revert-domain %q", domain)
	}
}

func runDaemon(store *state.Store, port int, deployerTag string, tailscaleIface string, watchdogSec int) error {
	ctx := context.Background()

	// Boot always restores the last confirmed state, synchronously,
	// before anything else — including before the RPC listener opens.
	// See FIREWALL.md: this is what makes a reboot safe. No dependency on
	// reaching Nornir or the tailnet control plane to get here. Both
	// domains are restored unconditionally, regardless of which one (if
	// either) last had a lease in flight: boot restore is not a lease
	// concept, it is "bring back everything this host ever proved worked".
	ruleset, err := store.Load(rpc.NftRuleset)
	if err != nil {
		return fmt.Errorf("boot restore: firewall: %w", err)
	}
	if len(ruleset) > 0 {
		log.Printf("ghostd: restoring last-confirmed firewall state (%d bytes)", len(ruleset))
	} else {
		log.Printf("ghostd: no last-confirmed firewall state on disk (fresh install) — nothing to restore")
	}
	if err := nft.Restore(ctx, nft.ExecRunner{}, ruleset); err != nil {
		return fmt.Errorf("boot restore: firewall: %w", err)
	}

	netconfigBlob, err := store.Load(rpc.NetconfigState)
	if err != nil {
		return fmt.Errorf("boot restore: netconfig: %w", err)
	}
	if len(netconfigBlob) > 0 {
		log.Printf("ghostd: restoring last-confirmed netconfig state (%d bytes)", len(netconfigBlob))
	} else {
		log.Printf("ghostd: no last-confirmed netconfig state on disk (fresh install) — nothing to restore")
	}
	if err := netconfig.Restore(ctx, netconfig.ExecRunner{}, netconfigBlob); err != nil {
		return fmt.Errorf("boot restore: netconfig: %w", err)
	}

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
