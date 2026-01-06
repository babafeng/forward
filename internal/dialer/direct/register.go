package direct

import (
	"forward/internal/config"
	"forward/internal/dialer"
)

func init() {
	dialer.Register("direct", newDialer)
}

func newDialer(cfg config.Config) (dialer.Dialer, error) {
	return dialer.NewDirect(cfg), nil
}
