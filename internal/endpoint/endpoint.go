package endpoint

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Endpoint describes a network endpoint expressed as a URL-like string.
//
// Supported examples:
//   - tcp://127.0.0.1:2222
//   - udp://0.0.0.0:5353
//   - socks5://user:pass@127.0.0.1:1080
//   - https://user:pass@localhost:443?bind=true

type Endpoint struct {
	Scheme string
	Host   string
	Port   int
	Path   string

	Raw string

	User *url.Userinfo

	Query url.Values

	RAddress string // remote address for reverse forward and port forward
	FAddress string // internal forward address(Services exposed internally to the public network)
}

func Parse(raw string) (Endpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Endpoint{}, fmt.Errorf("empty endpoint")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return Endpoint{}, fmt.Errorf("parse endpoint: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		return Endpoint{}, fmt.Errorf("endpoint scheme is required: %q", raw)
	}
	if u.Host == "" {
		return Endpoint{}, fmt.Errorf("endpoint host is required: %q", raw)
	}

	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return Endpoint{}, fmt.Errorf("endpoint must include host:port: %q: %w", raw, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return Endpoint{}, fmt.Errorf("invalid port %q in %q", portStr, raw)
	}

	raddr := u.Host
	faddr := strings.TrimLeft(u.Path, "/")
	if faddr == "" {
		raddr = ""
	}

	e := Endpoint{
		Raw:    raw,
		Scheme: scheme,
		Host:   host,
		Port:   port,
		User:   u.User,
		Path:   u.Path,
		Query:  u.Query(),

		RAddress: raddr,
		FAddress: faddr,
	}
	return e, nil
}

func (e Endpoint) Address() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
}

func (e Endpoint) String() string {
	u := url.URL{
		Scheme: e.Scheme,
		Host:   e.Address(),
	}
	if e.User != nil {
		u.User = e.User
	}
	if len(e.Query) > 0 {
		u.RawQuery = e.Query.Encode()
	}
	return u.String()
}

func (e Endpoint) HasUserPass() bool {
	if e.User == nil {
		return false
	}
	_, hasPass := e.User.Password()
	return e.User.Username() != "" || hasPass
}

func (e Endpoint) UserPass() (user, pass string, ok bool) {
	if e.User == nil {
		return "", "", false
	}
	user = e.User.Username()
	pass, _ = e.User.Password()
	if user == "" && pass == "" {
		return "", "", false
	}
	return user, pass, true
}
