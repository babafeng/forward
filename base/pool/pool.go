package pool

import "sync"

var (
	defaultSize = 64 * 1024

	pool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, defaultSize)
			return &b
		},
	}
)

func Get() []byte {
	bp := pool.Get().(*[]byte)
	b := *bp
	return b[:defaultSize]
}

func Put(b []byte) {
	if cap(b) < defaultSize {
		return
	}
	b = b[:cap(b)]
	pool.Put(&b)
}

func GetWithSize(size int) []byte {
	if size <= defaultSize {
		return Get()
	}
	return make([]byte, size)
}
