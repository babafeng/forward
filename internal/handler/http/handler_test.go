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

	"forward/base/logging"
	"forward/internal/chain"
	corehandler "forward/internal/handler"
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

func TestHTTPConnectionLogsIncludeTargetAndRoute(t *testing.T) {
	var out bytes.Buffer
	logger := logging.New(logging.Options{
		Level: logging.LevelDebug,
		Out:   &out,
		Err:   &out,
	})
	h := &Handler{
		options: corehandler.Options{Logger: logger},
	}
	ctx := context.WithValue(context.Background(), connInfoKey{}, connInfo{
		remote: "192.168.31.77:58799",
		local:  "192.168.31.180:33333",
	})
	route := chain.NewRoute(&chain.Node{Display: "us-node"})

	h.logHTTPConnectionInfo(ctx, "", "www.gstatic.com:443")
	h.logHTTPConnectionDebug(ctx, "", "www.gstatic.com:443", route)

	got := out.String()
	if !strings.Contains(got, "HTTP connection 192.168.31.77:58799 -> 192.168.31.180:33333 -> www.gstatic.com:443") {
		t.Fatalf("info log missing target path, got: %s", got)
	}
	if !strings.Contains(got, "HTTP connection 192.168.31.77:58799 -> 192.168.31.180:33333 -> www.gstatic.com:443 via [us-node]") {
		t.Fatalf("debug log missing route summary, got: %s", got)
	}
}

func TestCloseNotifyConnContextDelegatesToInnerConn(t *testing.T) {
	ctx := context.WithValue(context.Background(), connInfoKey{}, connInfo{
		remote: "192.168.31.77:58799",
		local:  "192.168.31.180:33333",
	})
	c := &closeNotifyConn{
		Conn: &contextConn{ctx: ctx},
	}

	got := c.Context()
	info, ok := got.Value(connInfoKey{}).(connInfo)
	if !ok {
		t.Fatal("closeNotifyConn.Context did not preserve connInfo")
	}
	if info.local != "192.168.31.180:33333" {
		t.Fatalf("connInfo.local = %q, want %q", info.local, "192.168.31.180:33333")
	}
}
