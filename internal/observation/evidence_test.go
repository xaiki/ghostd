package observation

import (
	"context"
	"strings"
	"testing"
)

type fake struct{ calls []string }

func (f *fake) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if name == "tailscale" {
		return []byte(`{"NetfilterMode":2,"Persist":{"PrivateNodeKey":"SECRET"}}`), nil
	}
	return []byte("captured"), nil
}
func TestCaptureUsesFixedReadOnlyCommandsAndRedactsPrefs(t *testing.T) {
	f := &fake{}
	e := Capture(context.Background(), f)
	if len(f.calls) != 4 || f.calls[0] != "iptables-save " || f.calls[1] != "ip6tables-save " {
		t.Fatal(f.calls)
	}
	if strings.Contains(e.Commands["tailscale-prefs"], "SECRET") || strings.Contains(e.Commands["tailscale-prefs"], "Persist") {
		t.Fatal("exported private prefs")
	}
	if !strings.Contains(e.Commands["tailscale-prefs"], "NetfilterMode") {
		t.Fatal("lost ownership evidence")
	}
}
