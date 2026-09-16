// Package state persists confirmed state and pre-apply rollback transactions.
package state

import (
	"fmt"
	"os"
	"path/filepath"
)

// Store persists opaque blobs atomically. DomainState is the durable transaction
// record; the executor for each domain owns the interpretation of its bytes.
type Store struct {
	dir string
}

// NewStore roots a Store at dir, creating it (mode 0700 — this holds the
// host's own firewall/netconfig state) if it does not exist yet.
func NewStore(dir string) (*Store, error) {
	// Revert runs under systemd with a different working directory.
	// Persist/pass the absolute location even when the CLI received a relative path.
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	dir = absolute
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
// half-written file. Callers hold Lock across read/modify/write transactions.
func (s *Store) Save(name string, data []byte) error {
	target := s.path(name)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("state: write %s: %w", tmp, err)
	}
	f, err := os.OpenFile(tmp, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("state: commit %s: %w", target, err)
	}
	dir, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
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
