//go:build dhcp

// Package replica runs a ghostd as a warm standby of another: it mirrors the
// authority's DHCP/identity ledger and configuration over the tailnet, holds
// every scope disabled while it does, and can be promoted — deliberately, and
// only once the old authority is known to be stopped — to continue from the
// mirror. There is no automatic failover: a standby that decided by itself that
// its peer was dead would, after a partition, be a second authority handing out
// the same addresses.
package replica

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/xaiki/ghostd/internal/addressbook"
	"github.com/xaiki/ghostd/internal/state"
	pb "github.com/xaiki/ghostd/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ConfigMirror is where the leader's DHCP configuration is kept until promotion.
const ConfigMirror = "replica-dhcp-config.json"

type Follower struct {
	Store    *state.Store
	Manager  *addressbook.Manager
	Leader   string
	Interval time.Duration

	mu       sync.Mutex
	lastSync time.Time
	lastErr  string
	cancel   context.CancelFunc
	promoted bool
}

func (f *Follower) dial() (pb.HostStateClient, func(), error) {
	conn, err := grpc.NewClient(f.Leader, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	return pb.NewHostStateClient(conn), func() { conn.Close() }, nil
}

// SyncOnce pulls everything the leader has that the standby lacks.
func (f *Follower) SyncOnce(ctx context.Context) error {
	client, done, err := f.dial()
	if err != nil {
		return err
	}
	defer done()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var events []addressbook.Event
	after := f.Manager.Store.ReplicaCursor()
	for {
		r, err := client.GetRegistry(ctx, &pb.RegistryRequest{AfterEvent: after, EventLimit: 1000})
		if err != nil {
			return fmt.Errorf("leader events: %w", err)
		}
		var page []addressbook.Event
		if err = json.Unmarshal([]byte(r.GetJson()), &page); err != nil {
			return err
		}
		events = append(events, page...)
		if len(page) < 1000 {
			break
		}
		after = page[len(page)-1].ID
	}
	sr, err := client.GetRegistry(ctx, &pb.RegistryRequest{})
	if err != nil {
		return fmt.Errorf("leader snapshot: %w", err)
	}
	var snap addressbook.Snapshot
	if err = json.Unmarshal([]byte(sr.GetJson()), &snap); err != nil {
		return err
	}
	state, err := client.GetState(ctx, &pb.GetStateRequest{})
	if err != nil {
		return fmt.Errorf("leader state: %w", err)
	}
	if _, err = f.Manager.Store.ApplyReplicated(events, &snap); err != nil {
		return err
	}
	if cfg := state.GetDhcpConfigJson(); cfg != "" {
		if _, err = addressbook.ParseConfig([]byte(cfg)); err != nil {
			return fmt.Errorf("leader configuration does not parse here: %w", err)
		}
		if err = f.Store.Save(ConfigMirror, []byte(cfg)); err != nil {
			return err
		}
	}
	return nil
}

// Run syncs until the context ends or the standby is promoted.
func (f *Follower) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	f.mu.Lock()
	f.cancel = cancel
	f.mu.Unlock()
	interval := f.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	for {
		err := f.SyncOnce(ctx)
		f.mu.Lock()
		if err != nil {
			f.lastErr = err.Error()
		} else {
			f.lastSync, f.lastErr = time.Now(), ""
		}
		f.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// LeaderAlive reports whether the leader still answers. Promotion refuses to
// proceed over a live leader unless forced.
func (f *Follower) LeaderAlive(ctx context.Context) bool {
	client, done, err := f.dial()
	if err != nil {
		return false
	}
	defer done()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err = client.GetRegistry(ctx, &pb.RegistryRequest{Scope: "-none-"})
	return err == nil
}

// Promote stops mirroring and starts serving the mirrored configuration. The
// caller holds the store lock and has established that the leader is stopped.
func (f *Follower) Promote(ctx context.Context) error {
	raw, err := f.Store.Load(ConfigMirror)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return fmt.Errorf("no leader configuration has been mirrored yet; nothing to promote")
	}
	cfg, err := addressbook.ParseConfig(raw)
	if err != nil {
		return err
	}
	f.mu.Lock()
	if f.cancel != nil {
		f.cancel()
	}
	f.mu.Unlock()
	f.Manager.SetStandby(false)
	if err = f.Manager.Apply(cfg, func() error {
		return f.Store.SaveExternallyManagedConfig("dhcp-v1", addressbook.ConfigFile, raw)
	}); err != nil {
		f.Manager.SetStandby(true) // still a standby: nothing was started
		go f.Run(context.Background())
		return fmt.Errorf("promotion failed, still a standby: %w", err)
	}
	f.mu.Lock()
	f.promoted = true
	f.mu.Unlock()
	return nil
}

// Status is the operator's view of the mirror.
func (f *Follower) Status() any {
	f.mu.Lock()
	defer f.mu.Unlock()
	age := int64(-1)
	if !f.lastSync.IsZero() {
		age = int64(time.Since(f.lastSync).Seconds())
	}
	return map[string]any{
		"leader": f.Leader, "promoted": f.promoted, "cursor": f.Manager.Store.ReplicaCursor(),
		"seconds_since_sync": age, "last_error": f.lastErr,
	}
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
