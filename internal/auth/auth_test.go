package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/xaiki/ghostd/internal/overlay"
)

type fakeWhoIs struct {
	resp *overlay.Caller
	err  error
}

func (f fakeWhoIs) Whois(ctx context.Context, remoteAddr string) (*overlay.Caller, error) {
	return f.resp, f.err
}

func taggedResponse(login string, tags ...string) *overlay.Caller {
	return &overlay.Caller{Tags: tags, Login: login}
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
	if !errors.Is(err, ErrNotOnOverlay) {
		t.Fatalf("expected ErrNotOnOverlay, got %v", err)
	}
}

func TestIdentifyOfANilNodeFails(t *testing.T) {
	a := NewAuthenticator(fakeWhoIs{}, "tag:stack-deployer")
	_, err := a.Identify(context.Background(), "100.64.0.1:1")
	if !errors.Is(err, ErrNotOnOverlay) {
		t.Fatalf("expected ErrNotOnOverlay for a WhoIs answer with no node, got %v", err)
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
			resp.Capabilities = overlay.Caps(DeployCapability, tc.raw)
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
	resp.Capabilities = overlay.Caps("example.com/other", `{"deploy":true}`)
	a := NewAuthenticator(fakeWhoIs{resp: resp}, "tag:stack-deployer")
	if _, err := a.AuthorizeDeployer(context.Background(), "100.64.0.1:1234"); err == nil {
		t.Fatal("unrelated capability authorized")
	}
}

func TestDeployerUsersAuthorizeByLoginWhereThereAreNoCapabilities(t *testing.T) {
	caller := taggedResponse("ops@example.com")
	plain := NewAuthenticator(fakeWhoIs{resp: caller}, "tag:stack-deployer")
	if _, err := plain.AuthorizeDeployer(context.Background(), "100.64.0.1:1"); err == nil {
		t.Fatal("an untagged caller without a capability was authorized")
	}
	byUser := NewAuthenticator(fakeWhoIs{resp: caller}, "tag:stack-deployer").WithDeployerUsers("ops@example.com")
	if _, err := byUser.AuthorizeDeployer(context.Background(), "100.64.0.1:1"); err != nil {
		t.Fatal(err)
	}
	other := NewAuthenticator(fakeWhoIs{resp: taggedResponse("guest@example.com")}, "tag:stack-deployer").WithDeployerUsers("ops@example.com")
	if _, err := other.AuthorizeDeployer(context.Background(), "100.64.0.1:1"); err == nil {
		t.Fatal("a login that is not listed was authorized")
	}
	if _, err := NewAuthenticator(fakeWhoIs{resp: caller}, "tag:x").WithDeployerUsers("").AuthorizeDeployer(context.Background(), "100.64.0.1:1"); err == nil {
		t.Fatal("an empty listed login matched a caller with no login")
	}
}

func TestAuthorizeReporterNeedsAStableNodeAndAReportGrant(t *testing.T) {
	ctx := context.Background()
	mk := func(c *overlay.Caller) *Authenticator {
		return NewAuthenticator(fakeWhoIs{resp: c}, "tag:stack-deployer")
	}
	report := &overlay.Caller{NodeID: "n1", Capabilities: overlay.Caps(ReportCapability, `{"report":true}`)}
	if _, err := mk(report).AuthorizeReporter(ctx, "100.64.0.1:1"); err != nil {
		t.Fatal(err)
	}
	// Reporting is not implied by mere presence on the overlay.
	if _, err := mk(&overlay.Caller{NodeID: "n1"}).AuthorizeReporter(ctx, "100.64.0.1:1"); err == nil {
		t.Fatal("a plain peer may not report")
	}
	// A report grant with no stable node ID cannot be attributed.
	if _, err := mk(&overlay.Caller{Capabilities: overlay.Caps(ReportCapability, `{"report":true}`)}).AuthorizeReporter(ctx, "100.64.0.1:1"); err == nil {
		t.Fatal("a report without a stable node ID was accepted")
	}
	// Deployers (tag or capability) may also report; a false grant does not count.
	if _, err := mk(&overlay.Caller{NodeID: "n2", Tags: []string{"tag:stack-deployer"}}).AuthorizeReporter(ctx, "100.64.0.1:1"); err != nil {
		t.Fatal(err)
	}
	if _, err := mk(&overlay.Caller{NodeID: "n3", Capabilities: overlay.Caps(ReportCapability, `{"report":false}`)}).AuthorizeReporter(ctx, "100.64.0.1:1"); err == nil {
		t.Fatal("report:false authorized")
	}
	if _, err := NewAuthenticator(fakeWhoIs{err: errors.New("gone")}, "t").AuthorizeReporter(ctx, "8.8.8.8:1"); !errors.Is(err, ErrNotOnOverlay) {
		t.Fatal(err)
	}
}

func TestIdentifyCopiesEveryFactAndNeverInventsCapabilities(t *testing.T) {
	caller := &overlay.Caller{Login: "ops@example.com", NodeID: "n1", DNSName: "n1.example.ts.net.", Tags: []string{"tag:a"}, Addresses: []string{"100.64.0.5"}}
	id, err := NewAuthenticator(fakeWhoIs{resp: caller}, "tag:x").Identify(context.Background(), "100.64.0.5:1")
	if err != nil || id.Login != "ops@example.com" || id.NodeID != "n1" || id.DNSName != "n1.example.ts.net." || len(id.Addresses) != 1 || id.CanDeploy || id.CanReport {
		t.Fatal(id, err)
	}
}
