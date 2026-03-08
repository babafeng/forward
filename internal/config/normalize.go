package config

import (
	"forward/base/endpoint"
	"strings"
)

func SplitCSVValues(values []string) []string {
	var out []string
	for _, raw := range values {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func PrimaryValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func ResolvePrimarySubscribe(primary, fallback string, urls []string) (string, []string) {
	subURL := primary
	if subURL == "" {
		subURL = fallback
	}
	subURLs := NormalizeSubscribeURLs(subURL, urls)
	if subURL == "" && len(subURLs) > 0 {
		subURL = subURLs[0]
	}
	return subURL, subURLs
}

func ParseEndpoints(raws []string) ([]endpoint.Endpoint, int, error) {
	out := make([]endpoint.Endpoint, 0, len(raws))
	for i, raw := range raws {
		ep, err := endpoint.Parse(raw)
		if err != nil {
			return nil, i, err
		}
		out = append(out, ep)
	}
	return out, -1, nil
}
