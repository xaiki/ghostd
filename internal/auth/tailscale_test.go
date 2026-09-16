package auth

import (
	"context"
	"errors"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type fakeWhoIs struct {
	resp *apitype.WhoIsResponse
	err  error
}

func (f fakeWhoIs) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	return f.resp, f.err
}

func taggedResponse(login string, tags ...string) *apitype.WhoIsResponse {
	return &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{Tags: tags},
		UserProfile: &tailcfg.UserProfile{LoginName: login},
	}
}

func TestIdentifyReturnsTheLoginAndTags(t *testing.T) {
	a := NewAuthenticator(fakeWhoIs{resp: taggedResponse("ops@example.com", "tag:stack-deployer")}, "tag:stack-deployer")
	id, err := a.Identify(context.Background(), "100.64.0.1:12345")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.Login != "ops@example.com" {
		t.Fatalf("got login %q", id.Login)
	}
	if !id.HasTag("tag:stack-deployer") {
		t.Fatalf("expected the deployer tag")
	}
}

func TestIdentifyOfAnUnknownPeerFails(t *testing.T) {
	a := NewAuthenticator(fakeWhoIs{err: errors.New("no such peer")}, "tag:stack-deployer")
	_, err := a.Identify(context.Background(), "8.8.8.8:1")
	if !errors.Is(err, ErrNotOnTailnet) {
		t.Fatalf("expected ErrNotOnTailnet, got %v", err)
	}
}

func TestIdentifyOfANilNodeFails(t *testing.T) {
	a := NewAuthenticator(fakeWhoIs{resp: &apitype.WhoIsResponse{}}, "tag:stack-deployer")
	_, err := a.Identify(context.Background(), "100.64.0.1:1")
	if !errors.Is(err, ErrNotOnTailnet) {
		t.Fatalf("expected ErrNotOnTailnet for a WhoIs answer with no node, got %v", err)
	}
}

func TestAuthorizeDeployerRequiresTheConfiguredTag(t *testing.T) {
	a := NewAuthenticator(fakeWhoIs{resp: taggedResponse("guest@example.com", "tag:something-else")}, "tag:stack-deployer")
	_, err := a.AuthorizeDeployer(context.Background(), "100.64.0.2:1")
	if err == nil {
		t.Fatalf("expected an untagged caller to be refused")
	}
}

func TestAuthorizeDeployerAcceptsTheTaggedCaller(t *testing.T) {
	a := NewAuthenticator(fakeWhoIs{resp: taggedResponse("deployer@example.com", "tag:stack-deployer")}, "tag:stack-deployer")
	id, err := a.AuthorizeDeployer(context.Background(), "100.64.0.3:1")
	if err != nil {
		t.Fatalf("AuthorizeDeployer: %v", err)
	}
	if id.Login != "deployer@example.com" {
		t.Fatalf("got %q", id.Login)
	}
}

func TestUntaggedCallerCanStillReadViaIdentify(t *testing.T) {
	// GetState carries no tag requirement -- only a reachable, resolvable
	// tailnet identity, which Identify alone proves.
	a := NewAuthenticator(fakeWhoIs{resp: taggedResponse("reader@example.com")}, "tag:stack-deployer")
	id, err := a.Identify(context.Background(), "100.64.0.4:1")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.HasTag("tag:stack-deployer") {
		t.Fatalf("this identity should not carry the deployer tag")
	}
}

func TestCapabilityAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		allow     bool
	}{
		{"explicit", `{"deploy":true}`, true},
		{"false", `{"deploy":false}`, false},
		{"empty", `{}`, false},
		{"null", `null`, false},
		{"wrong type", `{"deploy":"true"}`, false},
		{"malformed", `{`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := taggedResponse("operator@example.com")
			resp.CapMap = tailcfg.PeerCapMap{DeployCapability: {tailcfg.RawMessage(tc.raw)}}
			a := NewAuthenticator(fakeWhoIs{resp: resp}, "tag:stack-deployer")
			id, err := a.AuthorizeDeployer(context.Background(), "100.64.0.1:1234")
			if (err == nil) != tc.allow {
				t.Fatalf("allowed=%v, error=%v", tc.allow, err)
			}
			if tc.allow && (id.Login != "operator@example.com" || len(id.Tags) != 0) {
				t.Fatal("user identity changed")
			}
		})
	}
}

func TestUnrelatedCapabilityDoesNotAuthorize(t *testing.T) {
	resp := taggedResponse("operator@example.com")
	resp.CapMap = tailcfg.PeerCapMap{"example.com/other": {`{"deploy":true}`}}
	a := NewAuthenticator(fakeWhoIs{resp: resp}, "tag:stack-deployer")
	if _, err := a.AuthorizeDeployer(context.Background(), "100.64.0.1:1234"); err == nil {
		t.Fatal("unrelated capability authorized")
	}
}
