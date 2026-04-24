//go:build !linux

package netmark

import "net"

func configureDialer(d *net.Dialer) {}
