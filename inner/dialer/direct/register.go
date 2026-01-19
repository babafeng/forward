package direct

import (
	"forward/inner/config"
	"forward/inner/dialer"
)

func init() {
	dialer.Register("direct", newDialer)
}

func newDialer(cfg config.Config) (dialer.Dialer, error) {
	return dialer.NewDirect(cfg), nil
}
