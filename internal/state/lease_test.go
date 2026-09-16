package state

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	calls [][]string
	fail  bool
}

func (f *fakeRunner) Run(name string, args ...string) error {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.fail {
		return fmt.Errorf("fake failure")
	}
	return nil
}

func TestArmCallsSystemdRunWithTheBinaryInRevertMode(t *testing.T) {
	runner := &fakeRunner{}
	leases := NewLeases("/opt/ghostd/ghostd", runner)
	leaseID := "abc123"

	if err := leases.Arm(leaseID, "firewall", 5*time.Minute); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("expected exactly one systemd-run call, got %d", len(runner.calls))
	}
	call := runner.calls[0]
	if call[0] != "systemd-run" {
		t.Fatalf("expected systemd-run, got %s", call[0])
	}
	joined := strings.Join(call, " ")
	if !strings.Contains(joined, "--on-active=300s") {
		t.Fatalf("expected a 300s deadline in %v", call)
	}
	if !strings.Contains(joined, "/opt/ghostd/ghostd") || !strings.Contains(joined, "--revert-lease="+leaseID) {
		t.Fatalf("expected the revert command in %v", call)
	}
	if !strings.Contains(joined, "--revert-domain=firewall") {
		t.Fatalf("expected the revert command to carry its own domain in %v", call)
	}
}

func TestArmRejectsNonPositiveTimeout(t *testing.T) {
	leases := NewLeases("/opt/ghostd/ghostd", &fakeRunner{})
	if err := leases.Arm("x", "firewall", 0); err == nil {
		t.Fatalf("expected an error for a zero timeout — an Apply with no revert deadline must be refused")
	}
}

func TestArmRejectsAnEmptyDomain(t *testing.T) {
	leases := NewLeases("/opt/ghostd/ghostd", &fakeRunner{})
	if err := leases.Arm("x", "", time.Minute); err == nil {
		t.Fatalf("expected an error for an empty domain — the revert command would not know what to restore")
	}
}

func TestCancelStopsTheArmedUnit(t *testing.T) {
	runner := &fakeRunner{}
	leases := NewLeases("/opt/ghostd/ghostd", runner)
	if err := leases.Arm("lease-1", "firewall", time.Minute); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if err := leases.Cancel("lease-1"); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected arm + cancel calls, got %v", runner.calls)
	}
	cancelCall := runner.calls[1]
	if cancelCall[0] != "systemctl" || cancelCall[1] != "stop" || cancelCall[2] != "smarthome-ghostd-revert-lease-1.timer" {
		t.Fatalf("expected systemctl stop, got %v", cancelCall)
	}
}

func TestCancelOfAnUnarmedLeaseIsAnError(t *testing.T) {
	leases := NewLeases("/opt/ghostd/ghostd", &fakeRunner{})
	if err := leases.Cancel("never-armed"); err == nil {
		t.Fatalf("expected an error — confirming a lease that was never armed (or already reverted) must not silently succeed")
	}
}

func TestCancelIsOneShotNotIdempotent(t *testing.T) {
	runner := &fakeRunner{}
	leases := NewLeases("/opt/ghostd/ghostd", runner)
	if err := leases.Arm("lease-1", "firewall", time.Minute); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if err := leases.Cancel("lease-1"); err != nil {
		t.Fatalf("first Cancel: %v", err)
	}
	if err := leases.Cancel("lease-1"); err == nil {
		t.Fatalf("a second Confirm on the same lease must not silently succeed")
	}
}

func TestNewLeaseIDsAreUniqueAndOpaque(t *testing.T) {
	a := NewLeaseID()
	b := NewLeaseID()
	if a == b {
		t.Fatalf("expected distinct lease ids")
	}
	if a == "" {
		t.Fatalf("expected a non-empty lease id")
	}
}

func TestIntegrationTimerCancellation(t *testing.T) {
	if os.Getenv("GHOSTD_SYSTEMD_INTEGRATION") != "1" {
		t.Skip("requires disposable Linux systemd")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "fired")
	binary := filepath.Join(dir, "revert")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n: > "+marker+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	// Fedora's disposable VM forbids systemd from executing tmp_t files.
	// Label only this temporary test executable like an installed binary.
	if exec.Command("selinuxenabled").Run() == nil {
		if out, err := exec.Command("chcon", "-t", "bin_t", binary).CombinedOutput(); err != nil {
			t.Fatalf("label test executable: %v: %s", err, out)
		}
	}
	leases := NewLeases(binary, ExecRunner{})
	id := NewLeaseID()
	if err := leases.Arm(id, "firewall", 2*time.Second, dir); err != nil {
		t.Fatal(err)
	}
	if err := leases.Cancel(id); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("cancelled timer still fired")
	}
	id = NewLeaseID()
	if err := leases.Arm(id, "firewall", time.Second, dir); err != nil {
		t.Fatal(err)
	}
	defer leases.Cancel(id)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := os.Stat(marker); err != nil {
		out, _ := exec.Command("systemctl", "status", unitName(id)+".timer", unitName(id)+".service", "--no-pager").CombinedOutput()
		t.Logf("systemd state: %s", out)
		t.Fatalf("unconfirmed timer did not fire: %v", err)
	}
}
