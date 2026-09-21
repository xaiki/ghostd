package state

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// The crash tests re-run this test binary as a child that SIGKILLs itself at a named
// step of a save (no deferred function, no flush, no cleanup: as a kill -9 or an OOM
// kill would end it), then inspect what the next boot would find.
func init() { RegisterDomain("dhcp-v1") }

func TestCrashChild(t *testing.T) {
	dir, point, op := os.Getenv("GHOSTD_CRASH_DIR"), os.Getenv("GHOSTD_CRASH_POINT"), os.Getenv("GHOSTD_CRASH_OP")
	if dir == "" {
		t.Skip("child only")
	}
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	crashHook = func(p string) {
		if p == point {
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
	}
	switch op {
	case "save":
		s.Save("blob.json", []byte("NEW-CONTENT-NEW-CONTENT"))
	case "external":
		s.SaveExternallyManagedConfig("dhcp-v1", "dhcp-config.json", []byte(`{"scopes":[],"new":true}`))
	}
	t.Fatal("the kill point was never reached:", point)
}

func crashAt(t *testing.T, dir, op, point string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$")
	cmd.Env = append(os.Environ(), "GHOSTD_CRASH_DIR="+dir, "GHOSTD_CRASH_POINT="+point, "GHOSTD_CRASH_OP="+op)
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); !ok || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("the child was not killed at %s: %v", point, err)
	}
}

func TestKillDuringSaveNeverExposesAPartialFile(t *testing.T) {
	old := []byte("OLD-CONTENT")
	for _, point := range []string{"after-tmp-write", "after-sync", "after-rename"} {
		t.Run(point, func(t *testing.T) {
			dir := t.TempDir()
			s, _ := NewStore(dir)
			if err := s.Save("blob.json", old); err != nil {
				t.Fatal(err)
			}
			crashAt(t, dir, "save", point)
			// The next boot.
			s2, _ := NewStore(dir)
			got, err := s2.Load("blob.json")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, old) && !bytes.Equal(got, []byte("NEW-CONTENT-NEW-CONTENT")) {
				t.Fatalf("a killed save left a torn file: %q", got)
			}
			if point == "after-rename" && bytes.Equal(got, old) {
				t.Fatal("a committed rename was lost")
			}
			// A stale temp file must not get in the way of the next save.
			if err := s2.Save("blob.json", []byte("LATER")); err != nil {
				t.Fatal(err)
			}
			if got, _ = s2.Load("blob.json"); string(got) != "LATER" {
				t.Fatal(string(got))
			}
			if _, err := os.Stat(filepath.Join(dir, "blob.json.tmp")); err == nil {
				t.Fatal("stale temp file survived a later save")
			}
		})
	}
}

// The two-file update (transaction record, then the live config) can be killed
// between them. The boot path treats the transaction record as authoritative and
// rewrites the live file from it, so the pair must always be resolvable to one state.
func TestKillBetweenTransactionRecordAndLiveConfigIsResolvable(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	oldCfg := []byte(`{"scopes":[]}`)
	if err := s.SaveDomain("dhcp-v1", DomainState{Confirmed: oldCfg}); err != nil {
		t.Fatal(err)
	}
	s.Save("dhcp-config.json", oldCfg)
	crashAt(t, dir, "external", "between-domain-and-legacy")
	s2, _ := NewStore(dir)
	d, err := s2.Domain("dhcp-v1", "dhcp-config.json")
	if err != nil {
		t.Fatal(err)
	}
	live, _ := s2.Load("dhcp-config.json")
	if !bytes.Contains(d.Confirmed, []byte(`"new":true`)) {
		t.Fatal("the transaction record is the boot truth and holds the new state:", string(d.Confirmed))
	}
	if !bytes.Equal(live, oldCfg) {
		t.Fatal("expected the live file to lag (that is the window under test):", string(live))
	}
	// What the boot path does (recoverDomain -> restore): rewrite the live file from
	// the confirmed record. After it, the pair agrees.
	if err := s2.Save("dhcp-config.json", d.Confirmed); err != nil {
		t.Fatal(err)
	}
	if live, _ = s2.Load("dhcp-config.json"); !bytes.Equal(live, d.Confirmed) {
		t.Fatal("not resolvable")
	}
	if d.Pending != nil {
		t.Fatal("a killed external update must not leave a pending lease")
	}
}
