package tests

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"forward/inner/config"
	"forward/inner/endpoint"
	"forward/inner/handler/udp"
	"forward/inner/logging"
)

type udpLimitMockConn struct {
	net.Conn
}

func (m *udpLimitMockConn) Read(b []byte) (n int, err error) {
	time.Sleep(100 * time.Millisecond)
	return 0, nil
}
func (m *udpLimitMockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *udpLimitMockConn) Close() error                       { return nil }
func (m *udpLimitMockConn) SetDeadline(t time.Time) error      { return nil }
func (m *udpLimitMockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *udpLimitMockConn) SetWriteDeadline(t time.Time) error { return nil }

type udpLimitMockDialer struct {
	dialCount int
	mu        sync.Mutex
}

func (m *udpLimitMockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	m.mu.Lock()
	m.dialCount++
	m.mu.Unlock()
	return &udpLimitMockConn{}, nil
}

func TestUDPHandler_SessionLimit(t *testing.T) {
	logger := logging.New(logging.Options{Level: logging.LevelInfo})
	maxSessions := 10
	cfg := config.Config{
		Logger:         logger,
		Forward:        &endpoint.Endpoint{Scheme: "udp", Host: "127.0.0.1", Port: 5555},
		MaxUDPSessions: maxSessions,
		UDPIdleTimeout: 1 * time.Second,
	}

	mDialer := &udpLimitMockDialer{}
	h := udp.New(cfg, mDialer)
	defer h.Close()

	lconn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer lconn.Close()

	ctx := context.Background()

	// Try to create more sessions than allowed
	totalRequests := 20
	for i := 0; i < totalRequests; i++ {
		srcAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10000 + i}
		h.Handle(ctx, lconn, []byte("hello"), srcAddr)
	}

	mDialer.mu.Lock()
	count := mDialer.dialCount
	mDialer.mu.Unlock()

	if count > maxSessions {
		t.Errorf("Dial count %d exceeded max sessions %d", count, maxSessions)
	} else if count < maxSessions {
		t.Errorf("Dial count %d is less than expected max sessions %d", count, maxSessions)
	} else {
		t.Logf("Successfully limited to %d sessions", count)
	}
}
