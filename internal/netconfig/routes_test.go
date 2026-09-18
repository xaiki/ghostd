package netconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type routeRunner struct {
	routes    []map[string]any
	mutations []string
}

func (r *routeRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := strings.Join(args, " ")
	if strings.Contains(command, "route show") {
		return json.Marshal(r.routes)
	}
	r.mutations = append(r.mutations, command)
	if strings.Contains(command, "route add") {
		r.routes = []map[string]any{{"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "flags": []any{"onlink"}, "protocol": float64(242)}}
		return nil, nil
	}
	if strings.Contains(command, "route del") {
		r.routes = []map[string]any{}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected command: %s", command)
}
func TestDefaultRouteIsAdditiveIdempotentAndRollsBackOnlyOwnAddition(t *testing.T) {
	ctx := context.Background()
	r := &routeRunner{routes: []map[string]any{}}
	ds := DesiredState{Actions: [][]string{{"default-route", "eth0", "192.0.2.1", "onlink"}}}
	undo, err := Snapshot(ctx, r, ds)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, r, ds); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, r, ds); err != nil {
		t.Fatal(err)
	}
	if len(r.mutations) != 1 {
		t.Fatal(r.mutations)
	}
	if err := Rollback(ctx, r, undo); err != nil {
		t.Fatal(err)
	}
	if len(r.routes) != 0 {
		t.Fatal("route not removed")
	}
	if err := Rollback(ctx, r, undo); err != nil {
		t.Fatal(err)
	}
}
func TestExistingGatewayIsNeverReplacedOrRemoved(t *testing.T) {
	ctx := context.Background()
	r := &routeRunner{routes: []map[string]any{{"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "flags": []any{"onlink"}}}}
	ds := DesiredState{Actions: [][]string{{"default-route", "eth0", "192.0.2.1", "onlink"}}}
	undo, err := Snapshot(ctx, r, ds)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, r, ds); err != nil {
		t.Fatal(err)
	}
	if err := Rollback(ctx, r, undo); err != nil {
		t.Fatal(err)
	}
	if len(r.mutations) != 0 {
		t.Fatal(r.mutations)
	}
	ds.Actions[0][2] = "192.0.2.254"
	if err := Apply(ctx, r, ds); err == nil {
		t.Fatal("replaced conflicting route")
	}
	if len(r.mutations) != 0 {
		t.Fatal(r.mutations)
	}
}
func TestGatewayValidation(t *testing.T) {
	for _, a := range [][]string{{"default-route", "eth0;bad", "192.0.2.1", "onlink"}, {"default-route", "eth0", "::1", "onlink"}, {"default-route", "eth0", "192.0.2.1", "yes"}} {
		if Validate(DesiredState{Actions: [][]string{a}}) == nil {
			t.Fatal(a)
		}
	}
}
