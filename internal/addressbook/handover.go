package addressbook

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	bolt "go.etcd.io/bbolt"
	"net"
	"reflect"
	"time"
)

// LegacyAuthority is a stopped, inspectable authority, not a second allocator.
// Production uses systemd; the isolated lab uses a real dnsmasq child process.
type LegacyAuthority interface {
	Stop() error
	Start() error
	ReadLeases() (string, error)
	WriteLeases(string) error
	Validate(Config) error
}

type HandoverJournal struct {
	Phase    string     `json:"phase"`
	Deadline int64      `json:"deadline"`
	Target   Config     `json:"target"`
	Previous Config     `json:"previous"`
	Legacy   LegacySpec `json:"legacy"`
	Snapshot string     `json:"snapshot,omitempty"`
	// Activated is persisted before ghostd may grant anything. Until it is set
	// the legacy lease file is still authoritative and rollback must not depend
	// on parsing or importing the snapshot; afterwards the current ledger is.
	Activated bool   `json:"activated,omitempty"`
	Error     string `json:"error,omitempty"`
	Revision  uint32 `json:"revision"`
}

type Handover struct {
	Manager    *Manager
	Legacy     LegacyAuthority
	SaveConfig func(Config) error
}

func (s *Store) HandoverJournal() (HandoverJournal, error) {
	var j HandoverJournal
	e := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(metaBucket)
		if b == nil {
			return nil
		}
		raw := b.Get([]byte("handover"))
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &j)
	})
	return j, e
}
func (s *Store) saveHandover(j HandoverJournal) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(metaBucket)
		if e != nil {
			return e
		}
		raw, e := json.Marshal(j)
		if e != nil {
			return e
		}
		return b.Put([]byte("handover"), raw)
	})
}
func disabled(c Config) Config {
	c = cloneConfig(c)
	for i := range c.Scopes {
		c.Scopes[i].Enabled = false
	}
	return c
}
func (h Handover) apply(c Config) error {
	return h.Manager.Apply(c, func() error { return h.SaveConfig(c) })
}

// Begin writes recovery intent before stopping dnsmasq. An unconfirmed takeover
// rolls back after the deadline; restart recovery resumes an interrupted rollback.
func (h Handover) Begin(target Config, spec LegacySpec, grace time.Duration) error {
	if err := target.Validate(); err != nil {
		return err
	}
	if grace < 30*time.Second || grace > 30*time.Minute {
		return fmt.Errorf("handover deadline must be 30..1800 seconds")
	}
	previous := h.Manager.Config()
	for _, s := range previous.Scopes {
		if s.Enabled {
			return fmt.Errorf("disable ghostd scopes before dnsmasq takeover")
		}
	}
	old, e := h.Manager.Store.HandoverJournal()
	if e != nil {
		return e
	}
	if old.Phase != "" && old.Phase != "rolled-back" {
		return fmt.Errorf("handover already exists in phase %s", old.Phase)
	}
	if e = h.Legacy.Validate(target); e != nil {
		return e
	}
	j := HandoverJournal{Phase: "stopping", Deadline: time.Now().Add(grace).Unix(), Target: target, Previous: previous, Legacy: spec, Revision: h.Manager.Store.Revision()}
	if e = h.Manager.Store.saveHandover(j); e != nil {
		return e
	}
	e = h.begin(&j)
	if e != nil {
		j.Error = e.Error()
		_ = h.Manager.Store.saveHandover(j)
		if recovery := h.Rollback(); recovery != nil {
			return fmt.Errorf("takeover: %v; rollback pending: %w", e, recovery)
		}
	}
	return e
}
func (h Handover) begin(j *HandoverJournal) error {
	if e := h.Legacy.Stop(); e != nil {
		return e
	}
	raw, e := h.Legacy.ReadLeases()
	if e != nil {
		return e
	}
	j.Snapshot = raw
	j.Phase = "snapshot"
	if e = h.Manager.Store.saveHandover(*j); e != nil {
		return e
	}
	doc, e := ParseDNSmasq(j.Target, raw)
	if e != nil {
		return e
	}
	if e = h.Manager.Store.ImportDocument(disabled(j.Target), doc); e != nil {
		return e
	}
	j.Activated = true
	if e = h.Manager.Store.saveHandover(*j); e != nil {
		return e
	}
	if e = h.apply(j.Target); e != nil {
		return e
	}
	j.Phase = "pending"
	return h.Manager.Store.saveHandover(*j)
}
func (h Handover) Confirm() error {
	j, e := h.Manager.Store.HandoverJournal()
	if e != nil {
		return e
	}
	if j.Phase == "confirmed" {
		return nil
	}
	if j.Phase != "pending" || time.Now().Unix() >= j.Deadline {
		return fmt.Errorf("no live takeover to confirm")
	}
	// Re-prove authoritative DNS over both transports before cancelling recovery.
	// Real DHCP renewal/new-client probes remain part of the isolated acceptance
	// lab; the production operator initiates those clients during the pending window.
	for _, scope := range j.Target.Scopes {
		if !scope.Enabled {
			continue
		}
		for _, network := range []string{"udp", "tcp"} {
			query := new(dns.Msg)
			query.SetQuestion(scope.Zone+".", dns.TypeSOA)
			reply, _, err := (&dns.Client{Net: network, Timeout: 2 * time.Second}).Exchange(query, net.JoinHostPort(scope.Server, "53"))
			if err != nil || reply == nil || !reply.Authoritative || reply.Rcode != dns.RcodeSuccess || len(reply.Answer) == 0 {
				return fmt.Errorf("scope %s DNS %s verification failed: %v", scope.ID, network, err)
			}
		}
	}

	if time.Now().Unix() >= j.Deadline {
		return fmt.Errorf("takeover expired during verification")
	}
	j.Phase = "confirmed"
	j.Deadline = 0
	return h.Manager.Store.saveHandover(j)
}
func (h Handover) Rollback() error {
	j, e := h.Manager.Store.HandoverJournal()
	if e != nil {
		return e
	}
	if j.Phase == "" || j.Phase == "rolled-back" {
		return nil
	}
	if j.Phase == "confirmed" && !reflect.DeepEqual(disabled(h.Manager.Config()), disabled(j.Target)) {
		return fmt.Errorf("DHCP configuration changed since takeover; reconcile it before rollback")
	}
	j.Phase = "rolling-back"
	if e = h.Manager.Store.saveHandover(j); e != nil {
		return e
	}
	if e = h.apply(disabled(j.Target)); e != nil {
		return e
	}
	if j.Activated {
		// ghostd may have granted leases: export the current ledger, whatever the
		// original snapshot held (it may have been empty). The snapshot parsed
		// when it was imported, so it parses again; re-import first so legacy
		// leases an interrupted import missed are not lost. Current ownership
		// wins over older expiries; never overwrite new grants.
		doc, e := ParseDNSmasq(j.Target, j.Snapshot)
		if e != nil {
			return e
		}
		current, e := h.Manager.Store.Snapshot("", "", 0)
		if e != nil {
			return e
		}
		live := map[string]bool{}
		for _, b := range current.Bindings {
			if b.State == "active" || b.State == "offered" || b.State == "declined" {
				live[string(bindingKey(b.Scope, b.Address))] = true
			}
		}
		var missing []ImportedLease
		for _, l := range doc.Leases {
			if !live[string(bindingKey(l.Scope, l.Address))] {
				missing = append(missing, l)
			}
		}
		doc.Leases = missing
		if e = h.Manager.Store.ImportDocument(disabled(j.Target), doc); e != nil {
			return e
		}
		current, e = h.Manager.Store.Snapshot("", "", 0)
		if e != nil {
			return e
		}
		text, e := ExportDNSmasq(current)
		if e != nil {
			return e
		}
		if e = h.Legacy.WriteLeases(text); e != nil {
			return e
		}
	}
	if e = h.apply(disabled(j.Previous)); e != nil {
		return e
	}
	if e = h.Legacy.Start(); e != nil {
		return e
	}
	j.Phase = "rolled-back"
	j.Deadline = 0
	return h.Manager.Store.saveHandover(j)
}

// NeedsRecovery reports whether the journal records a takeover that must be
// rolled back: interrupted before pending, mid-rollback, or past its deadline.
func (j HandoverJournal) NeedsRecovery() bool {
	switch j.Phase {
	case "stopping", "snapshot", "rolling-back":
		return true
	case "pending":
		return time.Now().Unix() >= j.Deadline
	}
	return false
}
func (h Handover) Recover() error {
	j, e := h.Manager.Store.HandoverJournal()
	if e != nil {
		return e
	}
	if j.NeedsRecovery() {
		return h.Rollback()
	}
	return nil
}

// SaveHandoverForTest lets other packages fabricate an interrupted journal.
func (s *Store) SaveHandoverForTest(j HandoverJournal) error { return s.saveHandover(j) }
