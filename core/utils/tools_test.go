package utils

import "testing"

func TestFixURLScheme(t *testing.T) {
	testCases := []struct {
		name string
		in   string
		want string
	}{
		{name: "http2 converted to https", in: "http2://example.com", want: "https://example.com"},
		{name: "unchanged https", in: "https://example.com", want: "https://example.com"},
		{name: "unchanged other scheme", in: "socks5://127.0.0.1:1080", want: "socks5://127.0.0.1:1080"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FixURLScheme(tc.in); got != tc.want {
				t.Fatalf("FixURLScheme(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
