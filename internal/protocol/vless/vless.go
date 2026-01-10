package vless

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
)

const (
	Version    = 0x00
	CommandTCP = 0x01
	CommandUDP = 0x02

	AddonFlowVision = "xtls-rprx-vision"
)

type UUID [16]byte

func ParseUUID(s string) (UUID, error) {
	var u UUID
	clean := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '-' {
			clean = append(clean, byte(c))
		}
	}
	if len(clean) != 32 {
		return u, fmt.Errorf("invalid uuid length: %d", len(clean))
	}
	_, err := hex.Decode(u[:], clean)
	return u, err
}

type Request struct {
	Version byte
	UUID    UUID
	Addons  []byte
	Command byte
	Port    uint16
	Address string
	Network string // "tcp" or "udp"
}

func ReadRequest(r io.Reader) (*Request, error) {
	buf := make([]byte, 1+16+1)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	req := &Request{
		Version: buf[0],
	}
	copy(req.UUID[:], buf[1:17])

	addonLen := buf[17]
	if addonLen > 0 {
		req.Addons = make([]byte, addonLen)
		if _, err := io.ReadFull(r, req.Addons); err != nil {
			return nil, err
		}
	}

	// Read Command
	cmdBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, cmdBuf); err != nil {
		return nil, err
	}
	req.Command = cmdBuf[0]

	// Read Port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return nil, err
	}
	req.Port = binary.BigEndian.Uint16(portBuf)

	// Read Address
	addrTypeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, addrTypeBuf); err != nil {
		return nil, err
	}
	addrType := addrTypeBuf[0]

	var host string
	switch addrType {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return nil, err
		}
		host = net.IP(ip).String()
	case 0x02: // Domain
		domainLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, domainLenBuf); err != nil {
			return nil, err
		}
		domainLen := int(domainLenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(r, domain); err != nil {
			return nil, err
		}
		host = string(domain)
	case 0x03: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return nil, err
		}
		host = net.IP(ip).String()
	default:
		return nil, fmt.Errorf("unknown address type: %d", addrType)
	}

	req.Address = fmt.Sprintf("%s:%d", host, req.Port)

	switch req.Command {
	case CommandTCP:
		req.Network = "tcp"
	case CommandUDP:
		req.Network = "udp"
	default:
		return nil, fmt.Errorf("unknown command: %d", req.Command)
	}

	return req, nil
}

func WriteResponse(w io.Writer, version byte, addons []byte) error {
	if len(addons) > 255 {
		return fmt.Errorf("addons too long")
	}
	buf := []byte{version, byte(len(addons))}
	buf = append(buf, addons...)
	_, err := w.Write(buf)
	return err
}

func ClientHandshake(w io.Writer, uuid UUID, targetAddr string, network string) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}

	var port uint16
	_, err = fmt.Sscanf(portStr, "%d", &port)
	if err != nil {
		return err
	}

	if _, err := w.Write([]byte{Version}); err != nil {
		return err
	}

	if _, err := w.Write(uuid[:]); err != nil {
		return err
	}

	// Addon Len (0)
	if _, err := w.Write([]byte{0x00}); err != nil {
		return err
	}

	cmd := byte(CommandTCP)
	if network == "udp" {
		cmd = CommandUDP
	}
	if _, err := w.Write([]byte{cmd}); err != nil {
		return err
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	if _, err := w.Write(portBuf); err != nil {
		return err
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4
			if _, err := w.Write([]byte{0x01}); err != nil {
				return err
			}
			if _, err := w.Write(ip4); err != nil {
				return err
			}
		} else {
			// IPv6
			if _, err := w.Write([]byte{0x03}); err != nil {
				return err
			}
			if _, err := w.Write(ip); err != nil {
				return err
			}
		}
	} else {
		// Domain
		if len(host) > 255 {
			return fmt.Errorf("domain too long")
		}
		if _, err := w.Write([]byte{0x02, byte(len(host))}); err != nil {
			return err
		}
		if _, err := w.Write([]byte(host)); err != nil {
			return err
		}
	}

	return nil
}
