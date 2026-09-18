package netconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
)

var routeDevice = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

func validateDefaultRoute(action []string) error {
	if len(action) != 4 || !routeDevice.MatchString(action[1]) || action[1] == "." || action[1] == ".." {
		return fmt.Errorf("invalid default route device")
	}
	ip, err := netip.ParseAddr(action[2])
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("default route requires an IPv4 unicast gateway")
	}
	if action[3] != "onlink" && action[3] != "offlink" {
		return fmt.Errorf("invalid default route onlink flag")
	}
	return nil
}

// routeState refuses changes to an existing default, including multipath/metrics.
// Exact existing routes are preserved, including their original protocol owner.
func routeState(ctx context.Context, runner Runner, action []string) (bool, bool, error) {
	raw, err := runner.Output(ctx, "ip", "-j", "-4", "route", "show", "table", "main", "default")
	if err != nil {
		return false, false, err
	}
	var routes []map[string]any
	if err := json.Unmarshal(raw, &routes); err != nil || routes == nil {
		return false, false, fmt.Errorf("default route observation invalid")
	}
	if len(routes) == 0 {
		return false, false, nil
	}
	if len(routes) != 1 {
		return false, false, fmt.Errorf("multiple default routes require explicit migration")
	}
	r := routes[0]
	for key := range r {
		switch key {
		case "dst", "gateway", "dev", "flags", "protocol", "scope", "type", "table", "metric":
		default:
			return false, false, fmt.Errorf("unsupported default route attribute %s", key)
		}
	}
	flags, _ := r["flags"].([]any)
	onlink := false
	for _, flag := range flags {
		if flag != "onlink" {
			return false, false, fmt.Errorf("unsupported route flag")
		}
		onlink = true
	}
	if r["dst"] != "default" || r["gateway"] != action[2] || r["dev"] != action[1] || onlink != (action[3] == "onlink") || (r["metric"] != nil && r["metric"] != float64(0)) || (r["type"] != nil && r["type"] != "unicast") {
		return false, false, fmt.Errorf("existing default route conflicts; refusing replacement")
	}
	owned := r["protocol"] == float64(242) || r["protocol"] == "242"
	return true, owned, nil
}

func routeArgs(verb string, action []string) []string {
	args := []string{"-4", "route", verb, "default", "via", action[2], "dev", action[1], "proto", "242"}
	if action[3] == "onlink" {
		args = append(args, "onlink")
	}
	return args
}
func ensureDefaultRoute(ctx context.Context, runner Runner, action []string) error {
	exists, _, err := routeState(ctx, runner, action)
	if err != nil || exists {
		return err
	}
	_, err = runner.Output(ctx, "ip", routeArgs("add", action)...)
	if err != nil {
		exists, _, check := routeState(ctx, runner, action)
		if check == nil && exists {
			return nil
		}
	}
	return err
}
