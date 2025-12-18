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

	return scheme, auth, addr
}
