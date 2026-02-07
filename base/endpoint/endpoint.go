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

	// 预处理：转义 userinfo 部分中的 / 字符（base64 密码可能包含 /）
	// 格式: scheme://userinfo@host:port/path
	if strings.Contains(raw, "ss://") {
		raw = escapeUserinfoSlash(raw)
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
		if _, hasPass := e.User.Password(); hasPass {
			u.User = url.UserPassword(e.User.Username(), "redacted")
		} else {
			u.User = e.User
		}
	}
	if len(e.Query) > 0 {
		u.RawQuery = e.Query.Encode()
	}
	return u.String()
}

func (e Endpoint) RedactedString() string {
	u := url.URL{
		Scheme: e.Scheme,
		Host:   e.Address(),
	}
	if e.User != nil {
		if strings.EqualFold(e.Scheme, "hysteria2") || strings.EqualFold(e.Scheme, "hy2") {
			u.User = url.User("redacted")
		} else if _, hasPass := e.User.Password(); hasPass {
			u.User = url.UserPassword(e.User.Username(), "redacted")
		} else {
			u.User = e.User
		}
	}
	if len(e.Query) > 0 {
		q := url.Values{}
		sensitiveKeys := []string{"key", "private_key", "pbk", "sid", "uuid", "token", "psk", "password", "secret", "ca", "obfs-password"}
		for k, v := range e.Query {
			isSensitive := false
			for _, sk := range sensitiveKeys {
				if strings.EqualFold(k, sk) {
					isSensitive = true
					break
				}
			}
			if isSensitive {
				q.Set(k, "redacted")
			} else {
				for _, val := range v {
					q.Add(k, val)
				}
			}
		}
		u.RawQuery = q.Encode()
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

// escapeUserinfoSlash 转义 URL userinfo 部分中的 / 字符
// 这对于 base64 编码的密码非常重要，因为 base64 可能包含 / 字符
// 格式: scheme://userinfo@host:port/path
func escapeUserinfoSlash(raw string) string {
	// 找到 scheme://
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd == -1 {
		return raw
	}
	afterScheme := raw[schemeEnd+3:]

	// 找到 @ 符号（userinfo 结束）
	atIndex := strings.LastIndex(afterScheme, "@")
	if atIndex == -1 {
		// 没有 userinfo
		return raw
	}

	userinfo := afterScheme[:atIndex]
	rest := afterScheme[atIndex:]

	// 转义 userinfo 中的 / 为 %2F
	escapedUserinfo := strings.ReplaceAll(userinfo, "/", "%2F")

	return raw[:schemeEnd+3] + escapedUserinfo + rest
}
