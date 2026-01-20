package tests

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"forward/inner/app"
	"forward/inner/config"
	"forward/base/endpoint"
	"forward/base/logging"
)

func TestTCPPortForwardEndToEnd(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start backend: %v", err)
	}
	defer backendLn.Close()

	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn) // echo
	}()

	listenPort := freeTCPPort(t)
	listenEP := mustParseEndpoint(t, fmt.Sprintf("tcp://127.0.0.1:%d", listenPort))
	forwardEP := mustParseEndpoint(t, fmt.Sprintf("tcp://%s", backendLn.Addr().String()))

	cfg := config.Config{
		Listen:   listenEP,
		Forward:  &forwardEP,
		Logger:   testLogger(),
		LogLevel: logging.LevelError,
		Mode:     config.ModePortForward,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runner, err := app.NewForwarder(cfg)
	if err != nil {
		t.Fatalf("new forwarder: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond) // allow listener to start

	client, err := net.DialTimeout("tcp", listenEP.Address(), time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer client.Close()

	payload := []byte("hello")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("unexpected echo: %q", string(buf))
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			t.Fatalf("forwarder error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("forwarder did not stop")
	}
}

func TestUDPPortForwardEndToEnd(t *testing.T) {
	backendConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("start udp backend: %v", err)
	}
	defer backendConn.Close()

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := backendConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = backendConn.WriteToUDP(buf[:n], addr)
		}
	}()

	listenPort := freeUDPPort(t)
	listenEP := mustParseEndpoint(t, fmt.Sprintf("udp://127.0.0.1:%d", listenPort))
	forwardEP := mustParseEndpoint(t, fmt.Sprintf("udp://%s", backendConn.LocalAddr().String()))

	cfg := config.Config{
		Listen:         listenEP,
		Forward:        &forwardEP,
		Logger:         testLogger(),
		LogLevel:       logging.LevelError,
		UDPIdleTimeout: time.Second,
		Mode:           config.ModePortForward,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runner, err := app.NewForwarder(cfg)
	if err != nil {
		t.Fatalf("new forwarder: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond) // allow listener to start

	client, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listenPort})
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer client.Close()

	payload := []byte("ping")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 64*1024)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf[:n]) != string(payload) {
		t.Fatalf("unexpected echo: %q", string(buf[:n]))
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			t.Fatalf("forwarder error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("forwarder did not stop")
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func testLogger() *logging.Logger {
	return logging.New(logging.Options{Level: logging.LevelError})
}

func mustParseEndpoint(t *testing.T, raw string) endpoint.Endpoint {
	t.Helper()
	ep, err := endpoint.Parse(raw)
	if err != nil {
		t.Fatalf("parse endpoint %q: %v", raw, err)
	}
	return ep
}
