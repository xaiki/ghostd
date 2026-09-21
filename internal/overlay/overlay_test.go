package overlay

import (
	"context"
	"testing"
)

type stub struct{ name string }

func (s stub) Name() string                                     { return s.name }
func (stub) ListenAddress(context.Context, int) (string, error) { return "", nil }
func (stub) Whois(context.Context, string) (*Caller, error)     { return nil, nil }
func (stub) Peers(context.Context) ([]Peer, error)              { return nil, ErrUnsupported }

func TestRegistrySelection(t *testing.T) {
	saved := factories
	defer func() { factories = saved }()
	factories = map[string]Factory{}
	if _, err := New("", Options{}); err == nil {
		t.Fatal("a build with no provider must say so")
	}
	Register("headscale", func(Options) (Provider, error) { return stub{"headscale"}, nil })
	if p, err := New("", Options{}); err != nil || p.Name() != "headscale" {
		t.Fatal("the only provider built in is the default:", p, err)
	}
	Register("tailscale", func(Options) (Provider, error) { return stub{"tailscale"}, nil })
	if p, _ := New("", Options{}); p.Name() != "tailscale" {
		t.Fatal("with several built in, tailscale is the default")
	}
	if p, _ := New("headscale", Options{}); p.Name() != "headscale" {
		t.Fatal("explicit choice ignored")
	}
	if _, err := New("wireguard", Options{}); err == nil {
		t.Fatal("a provider that is not built in was selected")
	}
	if n := Names(); len(n) != 2 || n[0] != "headscale" {
		t.Fatal(n)
	}
}
