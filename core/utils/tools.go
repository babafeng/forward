package utils

import "strings"




func FixURLScheme(forwardURLs []string) []string {
	for i, url := range forwardURLs {
		if strings.HasPrefix(url, "http2") {
			forwardURLs[i] = "https" + strings.TrimPrefix(url, "http2")
		}
	}
	return forwardURLs
}