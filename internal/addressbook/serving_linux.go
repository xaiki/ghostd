//go:build linux

package addressbook

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// socketInodesForUDPPorts returns the inodes of UDP sockets bound to any of the
// given local ports, from /proc/net/udp and udp6.
func socketInodesForUDPPorts(ports ...int) (map[string]bool, error) {
	want := map[int]bool{}
	for _, p := range ports {
		want[p] = true
	}
	inodes := map[string]bool{}
	for _, table := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		f, err := os.Open(table)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 {
				continue
			}
			_, port, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			n, err := strconv.ParseInt(port, 16, 32)
			if err == nil && want[int(n)] {
				inodes[fields[9]] = true
			}
		}
		f.Close()
	}
	return inodes, nil
}

// processOwnsUDPPort reports whether pid holds a socket bound to one of the
// ports. It is what "the restored allocator is actually serving" means: the
// service being active proves only that a process exists.
func processOwnsUDPPort(pid int, ports ...int) (bool, error) {
	if pid <= 0 {
		return false, fmt.Errorf("no main process")
	}
	inodes, err := socketInodesForUDPPorts(ports...)
	if err != nil || len(inodes) == 0 {
		return false, err
	}
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		link, err := os.Readlink(dir + "/" + e.Name())
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		if inodes[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] {
			return true, nil
		}
	}
	return false, nil
}
