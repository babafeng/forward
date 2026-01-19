package pool

import "sync"

var (
	defaultSize = 64 * 1024

	pool = sync.Pool{
		New: func() interface{} {
			return make([]byte, defaultSize)
		},
	}
)

func Get() []byte {
	b := pool.Get().([]byte)
	return b[:cap(b)]
}

func Put(b []byte) {
	if cap(b) < defaultSize {
		return
	}
	pool.Put(b[:cap(b)])
}

func GetWithSize(size int) []byte {
	if size <= defaultSize {
		return Get()
	}
	return make([]byte, size)
}
