package pool

import "sync"

var (
	// defaultSize is the default size for buffers.
	// 64KB is common for UDP packets (max 65535) and TCP handling.
	defaultSize = 64 * 1024

	pool = sync.Pool{
		New: func() interface{} {
			return make([]byte, defaultSize)
		},
	}
)

// Get returns a byte slice from the pool.
// The returned slice has length equal to the default size (64KB).
func Get() []byte {
	return pool.Get().([]byte)
}

// Put returns a byte slice to the pool.
// It is safe to ignore the return from a function if you don't call Put,
// but it is recommended to reduce GC pressure.
func Put(b []byte) {
	if cap(b) < defaultSize {
		// Don't put back small buffers
		return
	}
	// Reset length to full capacity before putting back
	// but strictly we just put the slice back.
	// Users of Get should expect 'dirty' data or cap usage.
	// Here we just put it back.
	pool.Put(b)
}

// GetWithSize returns a byte slice with at least the given capacity.
// Currently it just returns the default pool item if it fits,
// or makes a new one. Ideally we might have multiple pools for different sizes.
func GetWithSize(size int) []byte {
	if size <= defaultSize {
		return Get()
	}
	return make([]byte, size)
}
