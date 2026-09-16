package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrips(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Save("nft-ruleset.json", []byte(`{"a":1}`)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Load("nft-ruleset.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != `{"a":1}` {
		t.Fatalf("got %q", got)
	}
}

func TestLoadOfNeverSavedNameIsNilNotError(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	got, err := store.Load("never-saved")
	if err != nil {
		t.Fatalf("Load: unexpected error %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for a never-confirmed state, got %q", got)
	}
}

func TestSaveOverwritesAtomicallyNeverLeavesAPartialFile(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Save("x", []byte("first")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Save("x", []byte("second, a bit longer")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Load("x")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != "second, a bit longer" {
		t.Fatalf("got %q", got)
	}
	// No stray .tmp file left behind by the rename.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("stray temp file left behind: %s", e.Name())
		}
	}
}

func TestNewStoreCreatesTheDirectoryPrivately(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "last-good")
	if _, err := NewStore(dir); err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected a directory")
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("expected mode 0700, got %o", info.Mode().Perm())
	}
}
