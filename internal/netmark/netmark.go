package netmark

import "net"

const SelfBypassMark = 0x80

func ConfigureDialer(d *net.Dialer) {
	if d == nil {
		return
	}
	configureDialer(d)
}
