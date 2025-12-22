package utils

import "strings"

func FixURLScheme(forwardURL string) string {
	if strings.HasPrefix(forwardURL, "http2") {
		return "https" + strings.TrimPrefix(forwardURL, "http2")
	}
	return forwardURL
}
