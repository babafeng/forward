package tests

import (
	"forward/inner/pool"
	"testing"
)

var (
	defaultSize = 64 * 1024
)

func TestPoolResetsLength(t *testing.T) {
	// 1. Get a buffer from the pool
	b := pool.Get()
	if len(b) != cap(b) {
		t.Fatalf("Initial Get() returned len=%d, cap=%d, expected len==cap", len(b), cap(b))
	}

	// 2. Simulate usage: truncate it
	b = b[:10]
	if len(b) != 10 {
		t.Fatalf("Failed to truncate buffer")
	}

	// 3. Put it back
	pool.Put(b)

	// 4. Validate Get() behavior strictly
	// Since sync.Pool doesn't guarantee we get the *same* object back,
	// we fundamentally verify that Get() *always* returns a full-capacity slice,
	// regardless of whether it's a new one or a recycled one.
	// However, to ensure Put() logic is correct (resetting it), we rely on
	// inspecting the code or running this many times if we wanted to catch a recycled one.
	// But crucially, if Get() is implemented correctly (resetting on retrieval),
	// then it doesn't matter what state Put() left it in (though Put resetting is good hygiene).
	// If the fix is in Get(), this test passes.

	for i := 0; i < 100; i++ {
		b2 := pool.Get()
		if len(b2) != cap(b2) {
			t.Errorf("Iteration %d: Get() returned len=%d, cap=%d", i, len(b2), cap(b2))
		}
		pool.Put(b2)
	}
}

func TestGetWithSize(t *testing.T) {
	size := 1024
	b := pool.GetWithSize(size)
	if len(b) < size {
		t.Errorf("GetWithSize(%d) returned len=%d", size, len(b))
	}

	// Test larger than default
	largeSize := defaultSize + 100
	b2 := pool.GetWithSize(largeSize)
	if len(b2) != largeSize {
		t.Errorf("GetWithSize(%d) returned len=%d", largeSize, len(b2))
	}
}
