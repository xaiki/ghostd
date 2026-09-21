//go:build mdns

package main

import (
	"context"
	"testing"
	"time"

	"github.com/xaiki/ghostd/internal/mdns"
	"github.com/xaiki/ghostd/internal/state"
)

func TestRestoreMDNSConfigValidatesThenPersists(t *testing.T) {
	store, _ := state.NewStore(t.TempDir())
	if err := restoreMDNSConfig(store, []byte(`{"host":"BAD","interfaces":["eth0"],"records":[{"service":"_smb._tcp","instance":"N","port":445}]}`)); err == nil {
		t.Fatal("an invalid snapshot was restored")
	}
	if raw, _ := store.Load(mdns.ConfigFile); len(raw) != 0 {
		t.Fatal("an invalid restore must not touch the live file:", string(raw))
	}
	if err := restoreMDNSConfig(store, nil); err != nil {
		t.Fatal(err)
	}
	if raw, _ := store.Load(mdns.ConfigFile); string(raw) != `{}` {
		t.Fatal("an empty snapshot means nothing advertised:", string(raw))
	}
}

func TestWatchMDNSConvergesAndSurvivesBadFiles(t *testing.T) {
	store, _ := state.NewStore(t.TempDir())
	svc := mdns.NewService()
	defer svc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { watchMDNS(ctx, store, svc); close(done) }()
	store.Save(mdns.ConfigFile, []byte(`not json`)) // a corrupt file is logged, never fatal
	time.Sleep(200 * time.Millisecond)
	store.Save(mdns.ConfigFile, []byte(`{}`))
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher ignored its context")
	}
	if !svc.Config().Empty() {
		t.Fatal("converged on an empty target")
	}
}
