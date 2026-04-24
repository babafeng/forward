package netmark

import (
	"net"
	"sync/atomic"
)

const SelfBypassMark = 0x80

var selfBypassEnabled atomic.Bool

func EnableSelfBypassMark() {
	selfBypassEnabled.Store(true)
}

func DisableSelfBypassMark() {
	selfBypassEnabled.Store(false)
}

func ConfigureDialer(d *net.Dialer) {
	if d == nil || !selfBypassEnabled.Load() {
		return
	}
	configureDialer(d)
}
