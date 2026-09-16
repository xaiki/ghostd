// Package state holds the two things that make a reboot or a bad Apply safe
// (FIREWALL.md): a store of the last state that ever passed Confirm, and a
// dead-man's-switch that reverts to it if Confirm never arrives.
package state

import (
	"fmt"
	"os"
	"path/filepath"
)

// Store persists named blobs of "last confirmed state" to disk — one file
// per domain (nft ruleset JSON today; netconfig/ingress blobs once Phase
// 4/5 land). Nothing here interprets the bytes: a domain package (internal/nft,
// eventually internal/netconfig) owns what "restore" means for its own blob.
type Store struct {
	dir string
}

// NewStore roots a Store at dir, creating it (mode 0700 — this holds the
// host's own firewall/netconfig state) if it does not exist yet.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state: create %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(name string) string {
	return filepath.Join(s.dir, name)
}

// Save writes data for name, atomically: a reader (including this
// process's own boot-time restore, or a crash mid-write) never observes a
// half-written file. Called only after a state has passed Confirm — see
// the package doc.
func (s *Store) Save(name string, data []byte) error {
	target := s.path(name)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("state: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("state: commit %s: %w", target, err)
	}
	return nil
}

// Load reads name's last-saved bytes, or (nil, nil) if nothing was ever
// saved for it — "never confirmed" is not an error, it is the honest state
// of a fresh install with nothing to restore yet.
func (s *Store) Load(name string) ([]byte, error) {
	data, err := os.ReadFile(s.path(name))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state: read %s: %w", s.path(name), err)
	}
	return data, nil
}
