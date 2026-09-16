package netconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Undo records exactly the files this apply may overwrite, including absence.
// Runtime interface changes remain additive: recovery never deletes an address
// or brings a link down. Persisted configuration and forwarding are restored.
type Undo struct {
	Files     map[string]*string `json:"files"`
	IPForward string             `json:"ip_forward,omitempty"`
}

func Snapshot(ctx context.Context, runner Runner, desired DesiredState) ([]byte, error) {
	u := Undo{Files: map[string]*string{}}
	for path := range desired.Files {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			u.Files[path] = nil
			continue
		}
		if err != nil {
			return nil, err
		}
		text := string(data)
		u.Files[path] = &text
	}
	for _, action := range desired.Actions {
		if action[0] == "sysctl" || action[0] == "forward" {
			out, err := runner.Output(ctx, "sysctl", "-n", "net.ipv4.ip_forward")
			if err != nil {
				return nil, err
			}
			u.IPForward = strings.TrimSpace(string(out))
			if u.IPForward != "0" && u.IPForward != "1" {
				return nil, fmt.Errorf("cannot snapshot ip_forward: %q", out)
			}
			break
		}
	}
	return json.Marshal(u)
}

func Rollback(ctx context.Context, runner Runner, blob []byte) error {
	var u Undo
	if err := json.Unmarshal(blob, &u); err != nil {
		return err
	}
	paths := map[string]string{}
	for path := range u.Files {
		paths[path] = ""
	}
	if err := Validate(DesiredState{Files: paths}); err != nil {
		return err
	}
	for _, path := range sortedKeys(paths) {
		content := u.Files[path]
		if content == nil {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		} else if err := writeFile(path, *content); err != nil {
			return err
		}
	}
	if u.IPForward != "" {
		if u.IPForward != "0" && u.IPForward != "1" {
			return fmt.Errorf("invalid forwarding snapshot")
		}
		_, err := runner.Output(ctx, "sysctl", "-q", "-w", "net.ipv4.ip_forward="+u.IPForward)
		return err
	}
	return nil
}
