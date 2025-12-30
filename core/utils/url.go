package utils

import (
	"net/url"
	"strings"
)

func URLParse(listenURL string) (string, *Auth, string) {
	// 解析 listenURL: [scheme://]addr
	var addr string
	var scheme string
	var auth *Auth

	if strings.Contains(listenURL, "://") {
		u, err := url.Parse(listenURL)
		if err == nil {
			scheme = u.Scheme
			addr = u.Host
			if u.User != nil {
				pass, _ := u.User.Password()
				auth = &Auth{User: u.User.Username(), Pass: pass}
			}
		} else {
			// URL.Parse 失败时的兜底配置
			parts := strings.Split(listenURL, "://")
			scheme = parts[0]
			addr = parts[1]
		}
	} else {
		addr = listenURL
	}

	if scheme == "" && strings.Contains(listenURL, "@") {
		u, err := url.Parse("auto://" + listenURL)
		if err == nil && u.User != nil && u.Host != "" {
			pass, _ := u.User.Password()
			auth = &Auth{User: u.User.Username(), Pass: pass}
			addr = u.Host
		}
	}

	return scheme, auth, addr
}

func RedactURL(rawURL string) string {
	parseURL := rawURL
	autoPrefix := false
	if !strings.Contains(rawURL, "://") && strings.Contains(rawURL, "@") {
		parseURL = "auto://" + rawURL
		autoPrefix = true
	}

	u, err := url.Parse(parseURL)
	if err != nil {
		return rawURL
	}
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			u.User = url.UserPassword(u.User.Username(), "*")
			redacted := strings.Replace(u.String(), ":%2A", ":*****", -1)
			if autoPrefix {
				return strings.TrimPrefix(redacted, "auto://")
			}
			return redacted
		}
	}
	if autoPrefix {
		return strings.TrimPrefix(u.String(), "auto://")
	}
	return u.String()
}

func ParseURLParams(listenURL string) url.Values {
	if strings.Contains(listenURL, "://") {
		u, err := url.Parse(listenURL)
		if err == nil {
			return u.Query()
		}
	}
	return nil
}

// SanitizeRequestURL removes embedded credentials while keeping path/query for logging.
func SanitizeRequestURL(u *url.URL) string {
	if u == nil {
		return ""
	}

	clean := *u
	clean.User = nil

	if clean.Scheme == "" && clean.Host == "" {
		return clean.RequestURI()
	}

	return clean.String()
}
