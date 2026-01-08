package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04
)

func EncodeAddr(host string, port int) ([]byte, error) {
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", port)
	}
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b := make([]byte, 0, 1+4+2)
			b = append(b, AtypIPv4)
			b = append(b, ip4...)
			b = append(b, p...)
			return b, nil
		}
		ip16 := ip.To16()
		if ip16 == nil {
			return nil, fmt.Errorf("invalid ip: %q", host)
		}
		b := make([]byte, 0, 1+16+2)
		b = append(b, AtypIPv6)
		b = append(b, ip16...)
		b = append(b, p...)
		return b, nil
	}

	if len(host) > 255 {
		return nil, fmt.Errorf("domain name too long: %d", len(host))
	}
	b := make([]byte, 0, 1+1+len(host)+2)
	b = append(b, AtypDomain, byte(len(host)))
	b = append(b, []byte(host)...)
	b = append(b, p...)
	return b, nil
}

func ReadAddr(r io.Reader, atyp byte) (string, int, error) {
	switch atyp {
	case AtypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host := net.IP(b).String()
		port, err := ReadPort(r)
		return host, port, err
	case AtypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host := net.IP(b).String()
		port, err := ReadPort(r)
		return host, port, err
	case AtypDomain:
		lb := []byte{0}
		if _, err := io.ReadFull(r, lb); err != nil {
			return "", 0, err
		}
		l := int(lb[0])
		d := make([]byte, l)
		if _, err := io.ReadFull(r, d); err != nil {
			return "", 0, err
		}
		host := string(d)
		port, err := ReadPort(r)
		return host, port, err
	default:
		return "", 0, fmt.Errorf("unknown atyp %d", atyp)
	}
}

func ReadPort(r io.Reader) (int, error) {
	pb := make([]byte, 2)
	if _, err := io.ReadFull(r, pb); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(pb)), nil
}
