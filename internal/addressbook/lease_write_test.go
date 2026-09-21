//go:build dnsmasq && dhcp

package addressbook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteLeasesReplacesAtomicallyAndKeepsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq.leases")
	if err := os.WriteFile(path, []byte("old\n"), 0640); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0640)
	l := SystemDNSmasq{Spec: LegacySpec{LeasePath: path}}
	if err := l.WriteLeases("new\n"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	info, _ := os.Stat(path)
	if string(got) != "new\n" || info.Mode().Perm() != 0640 {
		t.Fatalf("content %q mode %v", got, info.Mode())
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".ghostd-leases-*")); len(left) != 0 {
		t.Fatal("temp file left behind:", left)
	}
}

func TestWriteLeasesRefusesSymlinkAndMissing(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	os.WriteFile(real, []byte("keep\n"), 0600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("no symlinks")
	}
	if err := (SystemDNSmasq{Spec: LegacySpec{LeasePath: link}}).WriteLeases("x\n"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatal("wrote through a symlink:", err)
	}
	if got, _ := os.ReadFile(real); string(got) != "keep\n" {
		t.Fatal("symlink target modified", got)
	}
	if err := (SystemDNSmasq{Spec: LegacySpec{LeasePath: filepath.Join(dir, "absent")}}).WriteLeases("x\n"); err == nil {
		t.Fatal("wrote a lease file that never existed")
	}
}

func TestWriteLeasesFailureLeavesOriginalIntact(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq.leases")
	os.WriteFile(path, []byte("original\n"), 0600)
	os.Chmod(dir, 0500) // temp file cannot be created
	defer os.Chmod(dir, 0700)
	if err := (SystemDNSmasq{Spec: LegacySpec{LeasePath: path}}).WriteLeases("new\n"); err == nil {
		t.Fatal("interrupted replacement reported success")
	}
	if got, _ := os.ReadFile(path); string(got) != "original\n" {
		t.Fatalf("original damaged: %q", got)
	}
}
