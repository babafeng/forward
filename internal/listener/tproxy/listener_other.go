//go:build !linux

package tproxy

import (
	"errors"
	"net"
)

func (l *Listener) listenTCP(addr string) (net.Listener, error) {
	return nil, errors.New("tproxy listener only supported on linux")
}

func (l *Listener) listenUDP(addr string) (*net.UDPConn, error) {
	return nil, errors.New("tproxy listener only supported on linux")
}

func readFromUDP(conn *net.UDPConn, b []byte) (n int, remoteAddr *net.UDPAddr, dstAddr *net.UDPAddr, err error) {
	return 0, nil, nil, errors.New("tproxy listener only supported on linux")
}
