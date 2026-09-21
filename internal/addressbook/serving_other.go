//go:build !linux

package addressbook

import "fmt"

func processOwnsUDPPort(int, ...int) (bool, error) {
	return false, fmt.Errorf("socket ownership check is only available on Linux")
}
