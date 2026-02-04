//go:build linux

package tproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func (l *Listener) listenTCP(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: l.controlTransparentTCP,
	}
	return lc.Listen(context.Background(), "tcp", addr)
}

func (l *Listener) listenUDP(addr string) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: l.controlTransparentUDP,
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("tproxy: listen packet is not udp")
	}
	return uc, nil
}

func (l *Listener) controlTransparentTCP(network, address string, c syscall.RawConn) error {
	var ctrlErr error
	err := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
			if l.logSockoptError("IP_TRANSPARENT", err) {
				ctrlErr = err
				return
			}
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
			if l.logSockoptError("IPV6_TRANSPARENT", err) {
				ctrlErr = err
				return
			}
		}
	})
	if err != nil {
		return err
	}
	return ctrlErr
}

func (l *Listener) controlTransparentUDP(network, address string, c syscall.RawConn) error {
	var ctrlErr error
	err := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
			if l.logSockoptError("IP_TRANSPARENT", err) {
				ctrlErr = err
				return
			}
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
			if l.logSockoptError("IP_RECVORIGDSTADDR", err) {
				ctrlErr = err
				return
			}
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
			if l.logSockoptError("IPV6_TRANSPARENT", err) {
				ctrlErr = err
				return
			}
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1); err != nil {
			if l.logSockoptError("IPV6_RECVORIGDSTADDR", err) {
				ctrlErr = err
				return
			}
		}
	})
	if err != nil {
		return err
	}
	return ctrlErr
}

func (l *Listener) logSockoptError(name string, err error) bool {
	if err == nil {
		return false
	}
	if errno, ok := err.(syscall.Errno); ok {
		switch errno {
		case unix.ENOPROTOOPT, unix.EINVAL, unix.EAFNOSUPPORT:
			return false
		}
	}
	if l.logger != nil {
		l.logger.Error("TPROXY setsockopt %s failed: %v", name, err)
	}
	return true
}

// ReadFromUDP reads a UDP packet from c, copying the payload into b and returning
// the original destination address from control messages.
func readFromUDP(conn *net.UDPConn, b []byte) (n int, remoteAddr *net.UDPAddr, dstAddr *net.UDPAddr, err error) {
	oob := make([]byte, 8192)
	n, oobn, _, remoteAddr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return 0, nil, nil, err
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, nil, nil, fmt.Errorf("parsing socket control message: %v", err)
	}

	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_RECVORIGDSTADDR {
			originalDstRaw := &unix.RawSockaddrInet4{}
			if err = binary.Read(bytes.NewReader(msg.Data), binary.LittleEndian, originalDstRaw); err != nil {
				return 0, nil, nil, fmt.Errorf("reading original destination address: %v", err)
			}

			pp := (*unix.RawSockaddrInet4)(unsafe.Pointer(originalDstRaw))
			p := (*[2]byte)(unsafe.Pointer(&pp.Port))
			dstAddr = &net.UDPAddr{
				IP:   net.IPv4(pp.Addr[0], pp.Addr[1], pp.Addr[2], pp.Addr[3]),
				Port: int(p[0])<<8 + int(p[1]),
			}
		} else if msg.Header.Level == unix.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			inet6 := &unix.RawSockaddrInet6{}
			if err = binary.Read(bytes.NewReader(msg.Data), binary.LittleEndian, inet6); err != nil {
				return 0, nil, nil, fmt.Errorf("reading original destination address: %v", err)
			}

			p := (*[2]byte)(unsafe.Pointer(&inet6.Port))
			dstAddr = &net.UDPAddr{
				IP:   net.IP(inet6.Addr[:]),
				Port: int(p[0])<<8 + int(p[1]),
				Zone: fmt.Sprintf("%d", inet6.Scope_id),
			}
		}
	}

	if dstAddr == nil {
		return 0, nil, nil, fmt.Errorf("unable to obtain original destination")
	}

	return
}
