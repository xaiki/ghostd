//go:build linux

package addressbook

import (
	"context"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"net"
	"syscall"
)

func listenDHCP(iface string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var socketErr error
		err := c.Control(func(fd uintptr) {
			socketErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
			if socketErr == nil {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
			}
		})
		if err != nil {
			return err
		}
		return socketErr
	}}
	// No SO_REUSEADDR/SO_REUSEPORT: never share a scope with another allocator.
	return lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:67")
}

func listenDHCP6(iface string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var e error
		err := c.Control(func(fd uintptr) { e = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface) })
		if err != nil {
			return err
		}
		return e
	}}
	conn, e := lc.ListenPacket(context.Background(), "udp6", "[::]:547")
	if e != nil {
		return nil, e
	}
	link, e := net.InterfaceByName(iface)
	if e != nil {
		conn.Close()
		return nil, e
	}
	pc := ipv6.NewPacketConn(conn)
	if e = pc.JoinGroup(link, &net.UDPAddr{IP: net.ParseIP("ff02::1:2")}); e != nil {
		conn.Close()
		return nil, e
	}
	return conn, nil
}
