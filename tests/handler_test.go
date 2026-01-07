package tests

import (
	"bytes"
	"context"
	"errors"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"forward/internal/config"
	"forward/internal/handler/http"
	"forward/internal/logging"
)

type mockDialer struct {
	dialErr error
	conn    net.Conn
}

func (m *mockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if m.dialErr != nil {
		return nil, m.dialErr
	}
	if m.conn != nil {
		return m.conn, nil
	}
	return nil, errors.New("not implemented")
}

func TestHandler_handleConnect_CanceledContext(t *testing.T) {
	// Setup logger to capture output
	var logBuf bytes.Buffer
	logger := logging.New(logging.Options{
		Level: logging.LevelDebug,
		Out:   &logBuf,
		Err:   &logBuf,
	})

	// Setup handler with mock dialer that returns context.Canceled
	cfg := config.Config{Logger: logger}
	mDialer := &mockDialer{dialErr: context.Canceled}
	h := http.New(cfg, mDialer)

	// Create a request with CONNECT method
	req := httptest.NewRequest(stdhttp.MethodConnect, "http://example.com:443", nil)
	w := httptest.NewRecorder()

	// Cancel the context to simulate client disconnect or timeout logic matching the mock
	// (Though the mock returns the error directly, we want to ensure consistent behavior)
	ctx, cancel := context.WithCancel(req.Context())
	cancel() // cancel immediately
	req = req.WithContext(ctx)

	// Invoke ServeHTTP
	h.ServeHTTP(w, req)

	// Check response status
	if w.Code != stdhttp.StatusBadGateway {
		t.Errorf("expected status 502, got %d", w.Code)
	}

	// Verify log output contains "dial canceled" (debug level) not "dial error"
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "Forward http connect dial canceled") {
		t.Errorf("expected log to contain 'Forward http connect dial canceled', got:\n%s", logOutput)
	}
	if strings.Contains(logOutput, "[ERROR]") {
		t.Errorf("expected log NOT to contain '[ERROR]', got:\n%s", logOutput)
	}
}

func TestHandler_handleConnect_GenericError(t *testing.T) {
	// Setup logger to capture output
	var logBuf bytes.Buffer
	logger := logging.New(logging.Options{
		Level: logging.LevelDebug,
		Out:   &logBuf,
		Err:   &logBuf,
	})

	// Setup handler with mock dialer that returns a generic error
	cfg := config.Config{Logger: logger}
	mDialer := &mockDialer{dialErr: errors.New("network failure")}
	h := http.New(cfg, mDialer)

	// Create a request with CONNECT method
	req := httptest.NewRequest(stdhttp.MethodConnect, "http://example.com:443", nil)
	w := httptest.NewRecorder()

	// Invoke ServeHTTP
	h.ServeHTTP(w, req)

	// Check response status
	if w.Code != stdhttp.StatusBadGateway {
		t.Errorf("expected status 502, got %d", w.Code)
	}

	// Verify log output contains "dial error" (error level)
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "Forward http connect dial error") {
		t.Errorf("expected log to contain 'Forward http connect dial error', got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "[ERROR]") {
		t.Errorf("expected log to contain '[ERROR]', got:\n%s", logOutput)
	}
}

func TestHandler_handleConnect_ContextCancelHang(t *testing.T) {
	// Setup logger
	var logBuf bytes.Buffer
	logger := logging.New(logging.Options{Level: logging.LevelDebug, Out: &logBuf, Err: &logBuf})
	cfg := config.Config{Logger: logger}

	// Mock dialer connecting to a pipe to simulate an open connection
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	mDialer := &mockDialer{conn: clientConn}

	h := http.New(cfg, mDialer)

	// Create request with CONNECT
	req := httptest.NewRequest(stdhttp.MethodConnect, "http://example.com:443", nil)
	// We do NOT use NewRecorder because it might implement Hijacker if the underlying type supports it,
	// but httptest.ResponseRecorder does NOT implement Hijacker by default, which is what we want
	// to test the fallback path.
	w := httptest.NewRecorder()

	// Create a context we can cancel
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)

	// Run valid handler in a goroutine
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(w, req)
		close(done)
	}()

	// Wait a bit to ensure it established connection and entered the copy loop
	time.Sleep(100 * time.Millisecond)

	// Cancel context
	cancel()

	// It should return promptly. If it hangs, this select will timeout.
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Handler hung and did not return after context cancellation")
	}
}
