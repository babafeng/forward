package tests

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"testing"
	"time"

	"forward/base/endpoint"
	"forward/internal/builder"
	"forward/internal/config"
	"forward/internal/handler"
	revhandler "forward/internal/handler/reverse"
	"forward/internal/listener"
	"forward/internal/metadata"
	"forward/internal/registry"
	rev "forward/internal/reverse"
	revclient "forward/internal/reverse/client"

	ctls "forward/internal/config/tls"
)

func TestReverseTCPOverTLS(t *testing.T) {
	backendAddr, backendStop := startTCPEchoServer(t)
	defer backendStop()

	user := url.UserPassword("user", "pass")
	serverPort := freeTCPPort(t)
	serverEP := buildEndpoint(t, "tls", "127.0.0.1", serverPort, user, url.Values{"bind": []string{"true"}})
	stopServer := startReverseTLSServer(t, serverEP)
	defer stopServer()

	bindPort := freeTCPPort(t)
	listenRaw := "rtcp://127.0.0.1:" + strconv.Itoa(bindPort) + "/" + backendAddr
	listenEP := mustParseEndpoint(t, listenRaw)
	forwardEP := buildEndpoint(t, "tls", "127.0.0.1", serverPort, user, nil)

	cfg := config.Config{
		Listen:           listenEP,
		Forward:          &forwardEP,
		Logger:           testLogger(),
		Insecure:         true,
		DialTimeout:      3 * time.Second,
		HandshakeTimeout: 3 * time.Second,
	}
	config.ApplyDefaults(&cfg)

	route, err := builder.BuildReverseRoute(cfg, []endpoint.Endpoint{forwardEP})
	if err != nil {
		t.Fatalf("build reverse route: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner := revclient.New(cfg, route, forwardEP)
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()

	bindAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(bindPort))
	conn, err := waitForTCP(bindAddr, 5*time.Second)
	if err != nil {
		cancel()
		t.Fatalf("wait for bind: %v", err)
	}
	defer conn.Close()

	assertEcho(t, conn, []byte("reverse-tls"))

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Log("reverse client shutdown timed out")
	}
}

func startReverseTLSServer(t *testing.T, ep endpoint.Endpoint) func() {
	t.Helper()
	cfg := config.Config{
		Listen: ep,
		Logger: testLogger(),
	}
	config.ApplyDefaults(&cfg)

	h := revhandler.NewHandler(
		handler.AuthOption(ep.User),
		handler.LoggerOption(cfg.Logger),
	)
	hmd := metadata.New(map[string]any{
		"handshake_timeout": cfg.HandshakeTimeout,
		"udp_idle":          cfg.UDPIdleTimeout,
		"max_udp_sessions":  cfg.MaxUDPSessions,
	})
	if err := h.Init(hmd); err != nil {
		t.Fatalf("reverse handler init: %v", err)
	}

	newListener := registry.ListenerRegistry().Get("tcp")
	if newListener == nil {
		t.Fatalf("listener not registered for scheme tcp")
	}

	ctx, cancel := context.WithCancel(context.Background())
	lopts := []listener.Option{
		listener.AddrOption(ep.Address()),
		listener.LoggerOption(cfg.Logger),
		listener.ContextOption(ctx),
	}
	if protos := rev.NextProtosForScheme("tls"); len(protos) > 0 {
		tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{NextProtos: protos})
		if err != nil {
			cancel()
			t.Fatalf("tls config: %v", err)
		}
		lopts = append(lopts, listener.TLSConfigOption(tlsCfg))
	}

	ln := newListener(lopts...)
	lmd := metadata.New(map[string]any{
		"handshake_timeout": cfg.HandshakeTimeout,
	})
	if err := ln.Init(lmd); err != nil {
		cancel()
		t.Fatalf("reverse listener init: %v", err)
	}

	return startService(t, ln, h, cancel)
}

func waitForTCP(addr string, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			return conn, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("timeout waiting for %s", addr)
}
