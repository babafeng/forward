package tproxy

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"time"

	"forward/internal/config"
)

const (
	maxSniffBytes = 8192
)

func sniffTCPConn(conn net.Conn, overrides map[string]bool, timeout time.Duration) ([]byte, string, string) {
	if overrides == nil || (!overrides["http"] && !overrides["tls"]) {
		return nil, "", ""
	}
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}
	buf := make([]byte, maxSniffBytes)
	n, err := conn.Read(buf)
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Time{})
	}
	if n == 0 {
		if err != nil {
			return nil, "", ""
		}
		return nil, "", ""
	}
	data := buf[:n]
	if overrides["http"] {
		if h := sniffHTTPHost(data); h != "" {
			return data, h, "http"
		}
	}
	if overrides["tls"] {
		if h := sniffTLSServerName(data); h != "" {
			return data, h, "tls"
		}
	}
	return data, "", ""
}

func sniffUDP(conn net.Conn, overrides map[string]bool, timeout time.Duration) (net.Conn, []byte, string, string) {
	if overrides == nil || !overrides["quic"] {
		return conn, nil, "", ""
	}
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		defer conn.SetReadDeadline(time.Time{})
	}

	buf := make([]byte, config.DefaultUDPBuffer)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return conn, nil, "", ""
	}
	data := buf[:n]
	if h := sniffQUICServerName(data); h != "" {
		return conn, data, h, "quic"
	}
	return conn, data, "", ""
}

func sniffHTTPHost(data []byte) string {
	lines := bytes.Split(data, []byte("\r\n"))
	if len(lines) == 0 {
		return ""
	}
	reqLine := string(lines[0])
	if !looksLikeHTTPMethod(reqLine) {
		return ""
	}

	// Absolute-form request target
	if parts := strings.Split(reqLine, " "); len(parts) >= 2 {
		if u := parts[1]; strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			if host := parseHostFromURL(u); host != "" {
				return host
			}
		}
	}

	for _, line := range lines[1:] {
		if len(line) == 0 {
			break
		}
		lower := bytes.ToLower(line)
		if bytes.HasPrefix(lower, []byte("host:")) {
			host := strings.TrimSpace(string(line[5:]))
			if host != "" {
				return normalizeHost(host)
			}
		}
	}
	return ""
}

func looksLikeHTTPMethod(line string) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "PATCH "}
	for _, m := range methods {
		if strings.HasPrefix(line, m) {
			return true
		}
	}
	return false
}

func parseHostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	host := raw
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	return normalizeHost(host)
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			return strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
		}
		return strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	if strings.Count(host, ":") == 1 {
		if h, _, err := net.SplitHostPort(host); err == nil {
			return h
		}
	}
	return host
}

func sniffTLSServerName(data []byte) string {
	if len(data) < 5 || data[0] != 0x16 {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recLen {
		return ""
	}
	hs := data[5:]
	if len(hs) < 4 || hs[0] != 0x01 {
		return ""
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return ""
	}
	p := hs[4:]
	if len(p) < 2+32+1 {
		return ""
	}
	p = p[2+32:]
	if len(p) < 1 {
		return ""
	}
	sidLen := int(p[0])
	if len(p) < 1+sidLen {
		return ""
	}
	p = p[1+sidLen:]
	if len(p) < 2 {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(p[:2]))
	if len(p) < 2+csLen {
		return ""
	}
	p = p[2+csLen:]
	if len(p) < 1 {
		return ""
	}
	compLen := int(p[0])
	if len(p) < 1+compLen {
		return ""
	}
	p = p[1+compLen:]
	if len(p) < 2 {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) < extLen {
		return ""
	}
	exts := p[:extLen]
	for len(exts) >= 4 {
		etype := binary.BigEndian.Uint16(exts[:2])
		elen := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if len(exts) < elen {
			return ""
		}
		if etype == 0x00 {
			data := exts[:elen]
			if len(data) < 2 {
				return ""
			}
			listLen := int(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
			if len(data) < listLen {
				return ""
			}
			for len(data) >= 3 {
				nameType := data[0]
				nameLen := int(binary.BigEndian.Uint16(data[1:3]))
				data = data[3:]
				if len(data) < nameLen {
					return ""
				}
				if nameType == 0 {
					return string(data[:nameLen])
				}
				data = data[nameLen:]
			}
			return ""
		}
		exts = exts[elen:]
	}
	return ""
}

func sniffQUICServerName(_ []byte) string {
	return ""
}
