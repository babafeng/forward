package utils

import (
	"fmt"
	"io"
	"net"
	"strconv"
)

// ReadSocks5Addr reads the address and port from a SOCKS5 request/response
// It assumes the caller has already read the first 3 bytes (VER, CMD, RSV) and the 4th byte (ATYP) is passed as argument
// Or we can design it to read ATYP as well?
// Let's design it to take the reader and the ATYP that was already read, OR just the reader if we assume we are at the ATYP byte?
// In both existing cases, the caller reads 4 bytes (VER, CMD, RSV, ATYP).
// So the reader is positioned at the address.
func ReadSocks5Addr(r io.Reader, atyp byte) (string, error) {
	var addr string
	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		addr = net.IP(ip).String()
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", err
		}
		addr = string(domain)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		addr = net.IP(ip).String()
	default:
		return "", fmt.Errorf("unknown address type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", err
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])

	return net.JoinHostPort(addr, strconv.Itoa(port)), nil
}

// WriteSocks5Addr writes a SOCKS5 address and port to the writer
// It handles IPv4, IPv6, and Domain names
func WriteSocks5Addr(w io.Writer, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	var port int
	fmt.Sscanf(portStr, "%d", &port)

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			if _, err := w.Write([]byte{0x01}); err != nil {
				return err
			}
			if _, err := w.Write(ip4); err != nil {
				return err
			}
		} else {
			if _, err := w.Write([]byte{0x04}); err != nil {
				return err
			}
			if _, err := w.Write(ip); err != nil {
				return err
			}
		}
	} else {
		if _, err := w.Write([]byte{0x03}); err != nil {
			return err
		}
		if _, err := w.Write([]byte{byte(len(host))}); err != nil {
			return err
		}
		if _, err := w.Write([]byte(host)); err != nil {
			return err
		}
	}

	if _, err := w.Write([]byte{byte(port >> 8), byte(port)}); err != nil {
		return err
	}

	return nil
}
