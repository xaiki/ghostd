package state

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

// DomainState atomically commits both the confirmed bytes and the removal of
// the pending lease. A timer cannot roll back a successfully confirmed push,
// even if the daemon crashes before stopping its systemd timer.
type DomainState struct {
	Confirmed []byte   `json:"confirmed,omitempty"`
	Pending   *Pending `json:"pending,omitempty"`
}

type Pending struct {
	Applied  bool      `json:"applied"` // Set only after every mutation succeeds.
	ID       string    `json:"id"`
	Deadline time.Time `json:"deadline"`
	Snapshot []byte    `json:"snapshot"`
	Target   []byte    `json:"target"`
	Peer     string    `json:"peer"`
}

func (s *Store) Dir() string { return s.dir }

// Lock serializes RPC mutations, boot recovery and the independent timer
// process. Keep it held across kernel changes as well as file changes.
func (s *Store) Lock() (func(), error) {
	f, err := os.OpenFile(s.path("transaction.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

var (
	domainsMu sync.RWMutex
	domains   = map[string]bool{"firewall": true, "netconfig": true}
)

// RegisterDomain admits a domain a compiled-in feature owns (dhcp-v1, mdns-v1).
// A domain whose feature is not built in stays unknown, so a stray transaction
// record for it can never be read or written.
func RegisterDomain(name string) {
	domainsMu.Lock()
	domains[name] = true
	domainsMu.Unlock()
}

func domainFile(domain string) (string, error) {
	domainsMu.RLock()
	known := domains[domain]
	domainsMu.RUnlock()
	if !known {
		return "", fmt.Errorf("unknown domain %q", domain)
	}
	return domain + "-transaction.json", nil
}

func (s *Store) Domain(domain, legacyName string) (DomainState, error) {
	name, err := domainFile(domain)
	if err != nil {
		return DomainState{}, err
	}
	data, err := s.Load(name)
	if err != nil {
		return DomainState{}, err
	}
	var d DomainState
	if len(data) == 0 {
		d.Confirmed, err = s.Load(legacyName)
		return d, err
	}
	err = json.Unmarshal(data, &d)
	return d, err
}

func (s *Store) SaveDomain(domain string, d DomainState) error {
	name, err := domainFile(domain)
	if err != nil {
		return err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return s.Save(name, data)
}

// SaveExternallyManagedConfig updates both boot restore state and the live
// config file when another durable transaction (DHCP handover) owns recovery.
// It must not race an ordinary Apply/Confirm lease; caller holds the store lock.
func (s *Store) SaveExternallyManagedConfig(domain, legacyName string, raw []byte) error {
	d, err := s.Domain(domain, legacyName)
	if err != nil {
		return err
	}
	if d.Pending != nil {
		return fmt.Errorf("finish pending %s configuration lease first", domain)
	}
	d.Confirmed = raw
	if err = s.SaveDomain(domain, d); err != nil {
		return err
	}
	return s.Save(legacyName, raw)
}
