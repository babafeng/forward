package net

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestBidirectionalFallbackWithoutCloseWrite(t *testing.T) {
	oldTimeout := noHalfCloseFallbackTimeout
	noHalfCloseFallbackTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		noHalfCloseFallbackTimeout = oldTimeout
	})

	inLocal, inPeer := net.Pipe()
	outLocal, outPeer := net.Pipe()
	t.Cleanup(func() {
		_ = inPeer.Close()
		_ = outPeer.Close()
	})

	go func() {
		_, _ = io.Copy(io.Discard, inPeer)
	}()

	go func() {
		_, _ = outPeer.Write([]byte("ping"))
		_ = outPeer.Close()
	}()

	start := time.Now()
	n, _, err := Bidirectional(context.Background(), inLocal, outLocal)
	if err != nil {
		t.Fatalf("Bidirectional returned error: %v", err)
	}
	if n <= 0 {
		t.Fatalf("Bidirectional copied bytes = %d, want > 0", n)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Bidirectional elapsed = %s, want <= 1s", elapsed)
	}
}
