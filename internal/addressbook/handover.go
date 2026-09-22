//go:build dnsmasq && dhcp

package addressbook

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"github.com/xaiki/ghostd/internal/wellknown"
	bolt "go.etcd.io/bbolt"
	"reflect"
	"sort"
	"strings"
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
	// Started/Finished bracket the transaction; ImportedLeases counts legacy
	// leases carried into each scope, which decides what client evidence a
	// confirmation can reasonably demand.
	Started        int64          `json:"started,omitempty"`
	Finished       int64          `json:"finished,omitempty"`
	ImportedLeases map[string]int `json:"imported_leases,omitempty"`
	// RequireEvidence makes Confirm demand observed client behaviour (below).
	RequireEvidence bool `json:"require_evidence,omitempty"`
	// Probes and their latest results.
	Probes       []Probe       `json:"probes,omitempty"`
	ProbeResults []ProbeResult `json:"probe_results,omitempty"`
	// AbandonedDelegations counts prefix delegations a rollback had to end.
	AbandonedDelegations int `json:"abandoned_delegations,omitempty"`
}

// ScopeEvidence is what the ledger saw from real clients since the takeover
// began: renewals of leases inherited from the legacy allocator, and fresh
// grants. Both are events the DHCP path only writes for a real client exchange.
type ScopeEvidence struct {
	Imported int `json:"imported_leases"`
	Renewals int `json:"renewals"`
	Grants   int `json:"fresh_grants"`
}

// HandoverStatus is the operator-facing progress view of a takeover.
type HandoverStatus struct {
	HandoverJournal
	RemainingSeconds int64                    `json:"remaining_seconds,omitempty"`
	Retryable        bool                     `json:"retryable"`
	Evidence         map[string]ScopeEvidence `json:"evidence,omitempty"`
	Missing          []string                 `json:"pending_verification,omitempty"`
	// ProbesPending lists probes that have not passed yet.
	ProbesPending []string `json:"probes_pending,omitempty"`
	HistoryCount  int      `json:"history_count"`
}

type Handover struct {
	Manager    *Manager
	Legacy     LegacyAuthority
	SaveConfig func(Config) error
	// RequireEvidence is recorded in the journal by Begin.
	RequireEvidence bool
	// Probes are active checks run, and required to pass, at confirmation.
	Probes []Probe
	// ProbeRunner runs one probe; nil means RunProbe. Tests substitute it.
	ProbeRunner func(context.Context, Probe, Config) ProbeResult
	// AllowPD lets the target carry prefix delegation. dnsmasq's lease file cannot
	// hold delegations, so rolling back abandons them: the operator must accept
	// that in advance.
	AllowPD bool
}

var handoverHistoryBucket = []byte("handover-history-v1")

// archive keeps a finished takeover (without the bulky snapshot) as audit
// history; the mutable journal only ever describes the latest one.
func (s *Store) archiveHandover(j HandoverJournal) error {
	j.Snapshot = ""
	j.Finished = s.now().Unix()
	return s.db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(handoverHistoryBucket)
		if e != nil {
			return e
		}
		id, e := b.NextSequence()
		if e != nil {
			return e
		}
		raw, e := json.Marshal(j)
		if e != nil {
			return e
		}
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], id)
		return b.Put(key[:], raw)
	})
}

// HandoverHistory lists finished takeovers, oldest first.
func (s *Store) HandoverHistory() ([]HandoverJournal, error) {
	var out []HandoverJournal
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(handoverHistoryBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var j HandoverJournal
			if e := json.Unmarshal(v, &j); e != nil {
				return e
			}
			out = append(out, j)
			return nil
		})
	})
	return out, err
}

// clientEvidence counts real client exchanges per enabled target scope after
// the takeover began.
func (s *Store) clientEvidence(j HandoverJournal) (map[string]ScopeEvidence, error) {
	out := map[string]ScopeEvidence{}
	for _, sc := range j.Target.Scopes {
		if sc.Enabled {
			out[sc.ID] = ScopeEvidence{Imported: j.ImportedLeases[sc.ID]}
		}
	}
	after := uint64(j.Revision)
	for {
		events, e := s.Events(after, 1000)
		if e != nil {
			return nil, e
		}
		for _, ev := range events {
			after = ev.ID
			ce, ok := out[ev.Binding.Scope]
			if !ok || !strings.HasPrefix(ev.Binding.Origin, "dhcp") || isProbeMAC(ev.Binding.MAC) {
				continue
			}
			switch ev.Kind {
			case "renew":
				ce.Renewals++
			case "grant":
				ce.Grants++
			}
			out[ev.Binding.Scope] = ce
		}
		if len(events) < 1000 {
			return out, nil
		}
	}
}

// missingEvidence lists what a confirmation would still want to see.
func missingEvidence(ev map[string]ScopeEvidence) []string {
	var missing []string
	for id, e := range ev {
		if e.Imported > 0 && e.Renewals == 0 {
			missing = append(missing, fmt.Sprintf("scope %s: no client has renewed an inherited lease yet", id))
		}
		if e.Grants == 0 {
			missing = append(missing, fmt.Sprintf("scope %s: no new client has been allocated an address yet", id))
		}
	}
	sort.Strings(missing)
	return missing
}

// Status reports progress, remaining time, retryability and, while pending,
// the client evidence gathered so far.
func (h Handover) Status() (HandoverStatus, error) {
	j, e := h.Manager.Store.HandoverJournal()
	if e != nil {
		return HandoverStatus{}, e
	}
	st := HandoverStatus{HandoverJournal: j}
	if hist, e := h.Manager.Store.HandoverHistory(); e == nil {
		st.HistoryCount = len(hist)
	}
	if j.Deadline > 0 {
		if left := j.Deadline - time.Now().Unix(); left > 0 {
			st.RemainingSeconds = left
		}
	}
	st.Retryable = j.Phase == "rolling-back" || (j.Phase == "pending" && j.NeedsRecovery())
	if j.Phase == "pending" || j.Phase == "confirmed" {
		if st.Evidence, e = h.Manager.Store.clientEvidence(j); e != nil {
			return st, e
		}
		if j.Phase == "pending" {
			st.Missing = missingEvidence(st.Evidence)
			passed := map[string]bool{}
			for _, r := range j.ProbeResults {
				if r.OK {
					passed[fmt.Sprintf("%+v", r.Probe)] = true
				}
			}
			for _, p := range j.Probes {
				if !passed[fmt.Sprintf("%+v", p)] {
					st.ProbesPending = append(st.ProbesPending, p.Kind+" probe "+p.Scope+p.Addr+p.Name)
				}
			}
		}
	}
	return st, nil
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
	for _, sc := range target.Scopes {
		if sc.PD != nil && !h.AllowPD {
			return fmt.Errorf("scope %s delegates prefixes, which dnsmasq's lease file cannot carry: a rollback would abandon them. Repeat the request with allow_pd to accept that, or add prefix delegation with an ordinary apply after the takeover", sc.ID)
		}
	}
	for _, p := range h.Probes {
		if err := p.validate(target); err != nil {
			return err
		}
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
	j := HandoverJournal{Phase: "stopping", Started: time.Now().Unix(), RequireEvidence: h.RequireEvidence, Probes: h.Probes, Deadline: time.Now().Add(grace).Unix(), Target: target, Previous: previous, Legacy: spec, Revision: h.Manager.Store.Revision()}
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
	j.ImportedLeases = map[string]int{}
	for _, l := range doc.Leases {
		j.ImportedLeases[l.Scope]++
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
	if j.RequireEvidence {
		ev, e := h.Manager.Store.clientEvidence(j)
		if e != nil {
			return e
		}
		if missing := missingEvidence(ev); len(missing) > 0 {
			return fmt.Errorf("client verification incomplete: %s", strings.Join(missing, "; "))
		}
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
			reply, _, err := (&dns.Client{Net: network, Timeout: 2 * time.Second}).Exchange(query, wellknown.HostPort(scope.Server, wellknown.PortDNS))
			if err != nil || reply == nil || !reply.Authoritative || reply.Rcode != dns.RcodeSuccess || len(reply.Answer) == 0 {
				return fmt.Errorf("scope %s DNS %s verification failed: %v", scope.ID, network, err)
			}
		}
	}

	if len(j.Probes) > 0 {
		results := h.RunProbes(context.Background(), j)
		j.ProbeResults = results
		if e := h.Manager.Store.saveHandover(j); e != nil {
			return e
		}
		var failed []string
		for _, r := range results {
			if !r.OK {
				failed = append(failed, fmt.Sprintf("%s probe: %s", r.Probe.Kind, r.Detail))
			}
		}
		if len(failed) > 0 {
			return fmt.Errorf("active verification failed: %s", strings.Join(failed, "; "))
		}
	}
	if time.Now().Unix() >= j.Deadline {
		return fmt.Errorf("takeover expired during verification")
	}
	j.Phase = "confirmed"
	j.Deadline = 0
	if e := h.Manager.Store.saveHandover(j); e != nil {
		return e
	}
	return h.Manager.Store.archiveHandover(j)
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
	if j.Activated {
		n, e := h.Manager.Store.abandonDelegations(j.Target)
		if e != nil {
			return e
		}
		j.AbandonedDelegations += n
	}
	if e = h.apply(disabled(j.Previous)); e != nil {
		return e
	}
	if e = h.Legacy.Start(); e != nil {
		return e
	}
	j.Phase = "rolled-back"
	j.Deadline = 0
	if e = h.Manager.Store.saveHandover(j); e != nil {
		return e
	}
	return h.Manager.Store.archiveHandover(j)
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

// abandonDelegations ends every live prefix delegation in the target's PD pools:
// the legacy allocator cannot serve them, and leaving them active would keep
// routing prefixes to routers nothing renews. The ledger keeps the history.
func (s *Store) abandonDelegations(target Config) (int, error) {
	pools := map[string]bool{}
	for _, sc := range target.Scopes {
		if sc.PD != nil {
			pools[sc.ID] = true
		}
	}
	if len(pools) == 0 {
		return 0, nil
	}
	now := s.now().Unix()
	count := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		var live []Binding
		if e := tx.Bucket(leaseBucket).ForEach(func(_, raw []byte) error {
			var b Binding
			if e := json.Unmarshal(raw, &b); e != nil {
				return e
			}
			if b.Origin == originPD && pools[b.Scope] && b.End > now && (b.State == "active" || b.State == "offered") {
				live = append(live, b)
			}
			return nil
		}); e != nil {
			return e
		}
		for _, b := range live {
			b.State, b.End, b.Evidence = "released", now, "abandoned: rolled back to the legacy allocator, which cannot serve delegations"
			if e := s.save(tx, b, "release"); e != nil {
				return e
			}
			count++
		}
		return nil
	})
	return count, err
}

// RunProbes runs every probe the takeover carries against the target the daemon
// is serving now.
func (h Handover) RunProbes(ctx context.Context, j HandoverJournal) []ProbeResult {
	run := h.ProbeRunner
	if run == nil {
		run = RunProbe
	}
	var out []ProbeResult
	for _, p := range j.Probes {
		out = append(out, run(ctx, p, j.Target))
	}
	return out
}

// Probe runs the journaled probes now and records what they found, without
// confirming.
func (h Handover) Probe(ctx context.Context) ([]ProbeResult, error) {
	j, e := h.Manager.Store.HandoverJournal()
	if e != nil {
		return nil, e
	}
	if j.Phase != "pending" {
		return nil, fmt.Errorf("probes run during a pending takeover")
	}
	if len(j.Probes) == 0 {
		return nil, fmt.Errorf("this takeover carries no probes")
	}
	j.ProbeResults = h.RunProbes(ctx, j)
	return j.ProbeResults, h.Manager.Store.saveHandover(j)
}
