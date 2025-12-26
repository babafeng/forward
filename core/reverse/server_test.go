package reverse

import "testing"

func TestIsSupportedReverseScheme(t *testing.T) {
	testCases := []struct {
		name   string
		scheme string
		want   bool
	}{
		{name: "tls", scheme: "tls", want: true},
		{name: "ssh", scheme: "ssh", want: true},
		{name: "quic", scheme: "quic", want: true},
		{name: "upper case", scheme: "TLS", want: true},
		{name: "unsupported http", scheme: "http", want: false},
		{name: "empty", scheme: "", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSupportedReverseScheme(tc.scheme); got != tc.want {
				t.Fatalf("isSupportedReverseScheme(%q) = %v, want %v", tc.scheme, got, tc.want)
			}
		})
	}
}
