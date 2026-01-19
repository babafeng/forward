package tests

import (
	"bufio"
	"fmt"
	"net"
	"testing"

	rproto "forward/inner/reverse/proto"
)

func TestSocks5BindNoAuth(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		br := bufio.NewReader(server)
		bw := bufio.NewWriter(server)
		host, port, _, err := rproto.Socks5ServerBind(br, bw, nil)
		if err != nil {
			done <- err
			return
		}
		if host != "0.0.0.0" || port != 8080 {
			done <- fmt.Errorf("unexpected bind request: %s:%d", host, port)
			return
		}
		done <- rproto.WriteBindSuccess(bw, host, port)
	}()

	if err := rproto.Socks5ClientBind(client, "", "", "0.0.0.0", 8080, false); err != nil {
		t.Fatalf("client bind failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestSocks5BindWithAuth(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		br := bufio.NewReader(server)
		bw := bufio.NewWriter(server)
		host, port, _, err := rproto.Socks5ServerBind(br, bw, func(u, p string) bool {
			return u == "user" && p == "pass"
		})
		if err != nil {
			done <- err
			return
		}
		if host != "127.0.0.1" || port != 9090 {
			done <- fmt.Errorf("unexpected bind request: %s:%d", host, port)
			return
		}
		done <- rproto.WriteBindSuccess(bw, host, port)
	}()

	if err := rproto.Socks5ClientBind(client, "user", "pass", "127.0.0.1", 9090, false); err != nil {
		t.Fatalf("client bind failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server error: %v", err)
	}
}
