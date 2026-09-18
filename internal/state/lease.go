package state

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/google/uuid"
)

// CommandRunner runs one command to completion — the seam tests fake, so a
// lease test never actually calls systemd-run/systemctl.
type CommandRunner interface {
	Run(name string, args ...string) error
}

// ExecRunner is the real CommandRunner: os/exec, nothing else.
type ExecRunner struct{}

func (ExecRunner) Run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}

// Leases arms and cancels the dead-man's-switch for in-flight Apply calls.
//
// Deliberately a *separate systemd unit* per lease (systemd-run), not an
// in-process timer: if ghostd itself crashes or is killed mid-Apply, an
// in-process timer dies with it and the safety net it exists for disappears
// at exactly the moment it matters most. systemd-run's unit keeps running
// under systemd regardless of whether ghostd's own process is alive, and its
// command is the ghostd binary itself in revert mode (`ghostd --revert-lease=…`,
// see cmd/ghostd/main.go) — reverting does not depend on the original process
// either.
type Leases struct {
	mu         sync.Mutex
	units      map[string]string // leaseID -> systemd transient unit name
	binaryPath string
	runner     CommandRunner
}

func NewLeases(binaryPath string, runner CommandRunner) *Leases {
	return &Leases{units: make(map[string]string), binaryPath: binaryPath, runner: runner}
}

func unitName(leaseID string) string {
	return "smarthome-ghostd-revert-" + leaseID
}

// NewLeaseID mints an opaque lease identifier — a caller has no business
// constructing or guessing one.
func NewLeaseID() string {
	return uuid.NewString()
}

// Arm schedules a revert after timeout unless Cancel is called first.
//
// domain travels with the revert command itself (--revert-domain=, next to
// --revert-lease=), not through any in-memory record on this struct or on
// the server that called Arm: the revert unit is a *separate process*
// (systemd-run spawns it independently, see the package doc), and it must
// be able to know which domain's last-confirmed state to restore even if
// the daemon that armed it has since crashed, restarted, or lost whatever
// it remembered about this lease. Its own argv is the one channel
// guaranteed to reach it.
func (l *Leases) Arm(leaseID string, domain string, timeout time.Duration, storeDir ...string) error {
	if timeout <= 0 {
		return fmt.Errorf("state: dead-man's-switch timeout must be positive, got %s", timeout)
	}
	if domain == "" {
		return fmt.Errorf("state: dead-man's-switch domain must not be empty")
	}
	unit := unitName(leaseID)
	args := []string{
		"--unit=" + unit,
		"--description=smarthome-ghostd dead-man's-switch revert",
		fmt.Sprintf("--on-active=%ds", int(timeout.Seconds())),
		"--timer-property=AccuracySec=100ms",
		"--property=Restart=on-failure",
		"--property=RestartSec=5s",
		"--",
		l.binaryPath, "--revert-lease=" + leaseID, "--revert-domain=" + domain,
	}
	if len(storeDir) > 0 {
		args = append(args, "--store-dir="+storeDir[0])
	}
	if err := l.runner.Run("systemd-run", args...); err != nil {
		return fmt.Errorf("state: arm dead-man's-switch for lease %s: %w", leaseID, err)
	}
	l.mu.Lock()
	l.units[leaseID] = unit
	l.mu.Unlock()
	return nil
}

// Cancel stops the timer after the durable transaction has been confirmed.
// A service already triggered by that timer observes no pending lease and exits.
// On a command failure keep the local entry so cleanup can be retried.
func (l *Leases) Cancel(leaseID string) error {
	l.mu.Lock()
	unit, armed := l.units[leaseID]
	l.mu.Unlock()
	if !armed {
		return fmt.Errorf("state: lease %s is not armed", leaseID)
	}
	if err := l.runner.Run("systemctl", "stop", unit+".timer"); err != nil {
		return fmt.Errorf("state: cancel dead-man's-switch for lease %s: %w", leaseID, err)
	}
	l.mu.Lock()
	delete(l.units, leaseID)
	l.mu.Unlock()
	return nil
}
