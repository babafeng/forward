package ss

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestHttpObfsConnWriteInjectsHeaderOnce(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	obfs := NewHttpObfsConn(client, "example.com", "14103")

	readCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		data, err := io.ReadAll(server)
		if err != nil {
			errCh <- err
			return
		}
		readCh <- data
	}()

	n, err := obfs.Write([]byte("first"))
	if err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if n != len("first") {
		t.Fatalf("first write reported %d bytes, want %d", n, len("first"))
	}

	n, err = obfs.Write([]byte("second"))
	if err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	if n != len("second") {
		t.Fatalf("second write reported %d bytes, want %d", n, len("second"))
	}

	if err := obfs.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	var got []byte
	select {
	case got = <-readCh:
	case err := <-errCh:
		t.Fatalf("read failed: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server side data")
	}

	if !bytes.Contains(got, []byte("GET / HTTP/1.1\r\n")) {
		t.Fatalf("request line missing, payload=%q", string(got))
	}
	if !bytes.Contains(got, []byte("\r\nHost: example.com:14103\r\n")) {
		t.Fatalf("host header missing, payload=%q", string(got))
	}
	if !bytes.Contains(got, []byte("\r\nConnection: keep-alive\r\n")) {
		t.Fatalf("connection header missing, payload=%q", string(got))
	}
	if !bytes.Contains(got, []byte("\r\nAccept: */*\r\n")) {
		t.Fatalf("accept header missing, payload=%q", string(got))
	}
	if !bytes.HasSuffix(got, []byte("firstsecond")) {
		t.Fatalf("payload suffix mismatch: got %q", string(got))
	}
}

func TestHttpObfsConnReadStripsHTTPHeader(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	obfs := NewHttpObfsConn(client, "example.com", "80")
	if err := obfs.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline failed: %v", err)
	}

	go func() {
		_, _ = server.Write([]byte("HTTP/1.1 200 OK\r\nServer: test\r\n\r\nabc"))
	}()

	buf := make([]byte, 16)
	n, err := obfs.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf[:n]) != "abc" {
		t.Fatalf("unexpected read payload: got %q, want %q", string(buf[:n]), "abc")
	}
}

func TestHttpObfsConnReadPassThroughWhenNoHTTPHeader(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	obfs := NewHttpObfsConn(client, "example.com", "80")
	if err := obfs.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline failed: %v", err)
	}

	go func() {
		_, _ = server.Write([]byte("xyz"))
	}()

	buf := make([]byte, 16)
	n, err := obfs.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf[:n]) != "xyz" {
		t.Fatalf("unexpected read payload: got %q, want %q", string(buf[:n]), "xyz")
	}
}
