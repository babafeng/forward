package tests

import (
	"testing"

	"forward/internal/pool"
)

func TestPoolGetPut(t *testing.T) {
	buf := pool.Get()
	if buf == nil {
		t.Fatal("Get() returned nil")
	}

	// 验证缓冲区大小
	if cap(buf) < 64*1024 {
		t.Errorf("buffer capacity = %d, want >= %d", cap(buf), 64*1024)
	}

	// 归还缓冲区不应 panic
	pool.Put(buf)
}

func TestPoolMultipleGetPut(t *testing.T) {
	buffers := make([][]byte, 10)

	// 获取多个缓冲区
	for i := range buffers {
		buffers[i] = pool.Get()
		if buffers[i] == nil {
			t.Fatalf("Get() returned nil at index %d", i)
		}
	}

	// 归还所有缓冲区
	for _, buf := range buffers {
		pool.Put(buf)
	}
}

func TestPoolPutSmallBuffer(t *testing.T) {
	// 归还小缓冲区不应 panic
	smallBuf := make([]byte, 100)
	pool.Put(smallBuf)
}

func TestPoolPutNil(t *testing.T) {
	// 归还 nil 不应 panic
	pool.Put(nil)
}
