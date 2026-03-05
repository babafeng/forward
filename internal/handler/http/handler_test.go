package http

import (
	"bytes"
	"context"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"testing"
	"time"
)

type testResponseWriter struct {
	header  stdhttp.Header
	body    bytes.Buffer
	status  int
	flushes int
}

func (w *testResponseWriter) Header() stdhttp.Header {
	if w.header == nil {
		w.header = make(stdhttp.Header)
	}
	return w.header
}

func (w *testResponseWriter) Write(p []byte) (int, error) {
	return w.body.Write(p)
}

func (w *testResponseWriter) WriteHeader(statusCode int) {
	w.status = statusCode
}

func (w *testResponseWriter) Flush() {
	w.flushes++
}

func TestStreamWithBodyFallbackWithoutCloseWrite(t *testing.T) {
	old := streamNoHalfCloseGrace
	streamNoHalfCloseGrace = 50 * time.Millisecond
	t.Cleanup(func() {
		streamNoHalfCloseGrace = old
	})

	h := &Handler{}
	w := &testResponseWriter{}
	upstream, peer := net.Pipe()
	defer peer.Close()

	// Drain request bytes; do not send any upstream response so streamWithBody
	// must rely on no-half-close fallback to terminate.
	go func() {
		_, _ = io.Copy(io.Discard, peer)
	}()

	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		h.streamWithBody(context.Background(), w, io.NopCloser(strings.NewReader("hello")), upstream, w)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("streamWithBody did not return within timeout")
	}

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("streamWithBody elapsed = %s, want <= 1s", elapsed)
	}
}
