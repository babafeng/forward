//go:build !linux

package netmark

import "net"

// TuneTCPConn 在非 Linux 平台是空操作。
func TuneTCPConn(*net.TCPConn) {}

// TuneUDPConn 在非 Linux 平台是空操作。
func TuneUDPConn(net.PacketConn) {}
