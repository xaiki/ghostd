// Package observation captures fixed read-only inputs for adoption. No supplied
// command, path or model output is ever executed.
package observation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

type Runner interface {
	Output(context.Context, string, ...string) ([]byte, error)
}
type Evidence struct {
	Version    int               `json:"version"`
	CapturedAt string            `json:"captured_at"`
	Commands   map[string]string `json:"commands"`
	Files      map[string]string `json:"files"`
	Errors     map[string]string `json:"errors"`
}

const limit = 4 * 1024 * 1024

var commands = []struct {
	key, name string
	args      []string
}{
	{"iptables-save", "iptables-save", nil},
	{"ip6tables-save", "ip6tables-save", nil},
	{"services", "systemctl", []string{"show", "ufw.service", "tailscaled.service", "nftables.service", "--property=Id,ActiveState,UnitFileState,FragmentPath"}},
	{"tailscale-prefs", "tailscale", []string{"debug", "prefs"}},
}
var paths = []string{"/etc/ufw/ufw.conf", "/etc/default/ufw", "/etc/ufw/before.rules", "/etc/ufw/before6.rules", "/etc/ufw/after.rules", "/etc/ufw/after6.rules", "/etc/ufw/user.rules", "/etc/ufw/user6.rules"}

func Capture(ctx context.Context, runner Runner) Evidence {
	evidence := Evidence{Version: 1, CapturedAt: time.Now().UTC().Format(time.RFC3339Nano), Commands: map[string]string{}, Files: map[string]string{}, Errors: map[string]string{}}
	for _, command := range commands {
		call, cancel := context.WithTimeout(ctx, 3*time.Second)
		raw, err := runner.Output(call, command.name, command.args...)
		cancel()
		if err != nil {
			evidence.Errors[command.key] = err.Error()
			continue
		}
		if len(raw) > limit {
			evidence.Errors[command.key] = "evidence exceeds size limit; not used"
			continue
		}
		if command.key == "tailscale-prefs" {
			// Never export authentication material or arbitrary future preferences.
			var prefs map[string]json.RawMessage
			if err := json.Unmarshal(raw, &prefs); err != nil {
				evidence.Errors[command.key] = "invalid JSON"
				continue
			}
			selected := map[string]json.RawMessage{}
			for _, key := range []string{"NetfilterMode", "NoSNAT", "AdvertiseRoutes", "WantRunning"} {
				if value, ok := prefs[key]; ok {
					selected[key] = value
				}
			}
			raw, _ = json.Marshal(selected)
		}
		evidence.Commands[command.key] = string(raw)
	}
	for _, path := range paths {
		raw, err := readFile(path)
		if err != nil {
			evidence.Errors[path] = err.Error()
			continue
		}
		evidence.Files[path] = string(raw)
	}
	return evidence
}

func readFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if len(raw) > limit {
		return nil, fmt.Errorf("evidence exceeds size limit")
	}
	return raw, err
}
