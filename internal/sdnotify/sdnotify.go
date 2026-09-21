// Package sdnotify sends the two systemd notify-protocol messages this
// daemon's unit needs (README/systemd unit: Type=notify, WatchdogSec=) —
// deliberately not a dependency on coreos/go-systemd for two lines of
// protocol that never changes.
package sdnotify

import (
	"net"
	"os"
)

func send(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		// Not running under systemd (a dev shell, a test) — silently a
		// no-op: the same "no watcher, no error" contract the rest of the
		// daemon follows, because this must never be why the daemon
		// fails to start.
		return nil
	}
	conn, err := net.Dial("unixgram", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// Ready tells systemd this unit finished starting — send only after the
// boot-time last-good restore has run and the RPC listener is open, never
// before: a systemd dependency ordered After= this unit is entitled to
// assume both are true once this fires.
func Ready() error { return send("READY=1") }

// Watchdog pets the watchdog timer (WatchdogSec= in the unit) — call this
// on an interval well under that value from a goroutine that only runs
// while the main serve loop is actually live, so a wedged (not crashed)
// daemon stops petting it and systemd restarts the unit.
func Watchdog() error { return send("WATCHDOG=1") }
