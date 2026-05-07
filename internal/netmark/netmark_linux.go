//go:build linux

package netmark

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func configureDialer(d *net.Dialer) {
	prev := d.Control
	d.Control = func(network, address string, c syscall.RawConn) error {
		if prev != nil {
			if err := prev(network, address, c); err != nil {
				return err
			}
		}

		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, SelfBypassMark)
		}); err != nil {
			return err
		}
		return sockErr
	}
}
