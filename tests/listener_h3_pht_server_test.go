package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	h3listener "forward/internal/listener/h3"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestCloseClosesStoredSessionConn(t *testing.T) {
	s := h3listener.NewServer("127.0.0.1:0")
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.ListenAndServe()
	}()

	addr := waitForAddr(t, s.Addr)
	token := authorizeTokenHTTP1(t, addr)
	if token == "" {
		_ = s.Close()
		t.Fatalf("empty token from authorize")
	}

	connCh := make(chan net.Conn, 1)
	acceptErrCh := make(chan error, 1)
	go func() {
		c, err := s.Accept()
		if err != nil {
			acceptErrCh <- err
			return
		}
		connCh <- c
	}()

	var conn net.Conn
	select {
	case conn = <-connCh:
	case err := <-acceptErrCh:
		_ = s.Close()
		t.Fatalf("accept failed: %v", err)
	case <-time.After(time.Second):
		_ = s.Close()
		t.Fatalf("accept timed out")
	}
	defer conn.Close()

	_ = s.Close()

	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("expected accepted conn to be closed after server close")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected EOF/closed error, got %v", err)
	}

	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatalf("ListenAndServe did not return after close")
	}
}

func TestListenAndServeHTTP3StartsCleanupLoop(t *testing.T) {
	oldTick := h3CleanupTickInterval
	oldTimeout := h3SessionIdleTimeout
	h3CleanupTickInterval = 10 * time.Millisecond
	h3SessionIdleTimeout = 5 * time.Millisecond
	t.Cleanup(func() {
		h3CleanupTickInterval = oldTick
		h3SessionIdleTimeout = oldTimeout
	})

	tlsConfig := mustMakeH3TLSConfig(t)
	addr := fmt.Sprintf("127.0.0.1:%d", freeUDPPort(t))
	s := h3listener.NewHTTP3Server(
		addr,
		&quic.Config{},
		h3listener.TLSConfigServerOption(tlsConfig),
		h3listener.ReadTimeoutServerOption(50*time.Millisecond),
	)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.ListenAndServe()
	}()

	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
	}
	defer rt.Close()
	client := &http.Client{
		Transport: rt,
		Timeout:   2 * time.Second,
	}

	token := authorizeTokenHTTP3(t, client, addr)
	if token == "" {
		_ = s.Close()
		t.Fatalf("empty token from authorize")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		code := pushTokenHTTP3(t, client, addr, token)
		if code == http.StatusForbidden {
			break
		}
		if time.Now().After(deadline) {
			_ = s.Close()
			t.Fatalf("expected stale session to be cleaned, got status %d", code)
		}
		time.Sleep(20 * time.Millisecond)
	}

	_ = s.Close()
	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatalf("ListenAndServe did not return after close")
	}
}

func waitForAddr(t *testing.T, addrFn func() net.Addr) string {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if addr := addrFn(); addr != nil {
			return addr.String()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server addr not ready")
	return ""
}

func authorizeTokenHTTP1(t *testing.T, addr string) string {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/authorize")
	if err != nil {
		t.Fatalf("authorize request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read authorize response failed: %v", err)
	}
	return strings.TrimPrefix(strings.TrimSpace(string(body)), "token=")
}

func authorizeTokenHTTP3(t *testing.T, client *http.Client, addr string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := client.Get("https://" + addr + "/authorize")
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				t.Fatalf("read authorize response failed: %v", readErr)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("authorize status = %d, want 200", resp.StatusCode)
			}
			return strings.TrimPrefix(strings.TrimSpace(string(body)), "token=")
		}
		if time.Now().After(deadline) {
			t.Fatalf("authorize request failed: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func pushTokenHTTP3(t *testing.T, client *http.Client, addr, token string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/push?token="+token, strings.NewReader("\n"))
	if err != nil {
		t.Fatalf("build push request failed: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("push request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func mustMakeH3TLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key failed: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate failed: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parse key pair failed: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
}
