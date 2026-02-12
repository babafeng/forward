package tests

import (
	"testing"

	"forward/base/endpoint"
	"forward/internal/config"
)

func TestShouldWarmup(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.Config
		want bool
	}{
		{
			name: "disabled without url",
			cfg:  config.Config{},
			want: false,
		},
		{
			name: "disabled without forward",
			cfg: config.Config{
				WarmupURL: "http://www.gstatic.com/generate_204",
			},
			want: false,
		},
		{
			name: "enabled with single forward",
			cfg: config.Config{
				WarmupURL: "http://www.gstatic.com/generate_204",
				Forward:   &endpoint.Endpoint{},
			},
			want: true,
		},
		{
			name: "enabled with forward chain",
			cfg: config.Config{
				WarmupURL:    "http://www.gstatic.com/generate_204",
				ForwardChain: []endpoint.Endpoint{{}},
			},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := appShouldWarmup(tc.cfg)
			if got != tc.want {
				t.Fatalf("shouldWarmup=%v want %v", got, tc.want)
			}
		})
	}
}
