package utils

import (
	"net"
	"regexp"
	"strconv"
)

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)

func IsValidHostPort(s string) bool {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}

	// 校验端口
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false
	}

	// 校验 IP
	if net.ParseIP(host) != nil {
		return true
	}

	// 校验域名
	if domainRegex.MatchString(host) {
		return true
	}

	return false
}
