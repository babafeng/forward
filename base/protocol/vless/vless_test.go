package vless

import (
	"bytes"
	"testing"
)

func TestClientHandshakeWrapsAddonsHandshake(t *testing.T) {
	uuid, err := ParseUUID("11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatal(err)
	}

	var plain bytes.Buffer
	if err := ClientHandshake(&plain, uuid, "example.com:443", "tcp"); err != nil {
		t.Fatal(err)
	}

	var wrapped bytes.Buffer
	if err := ClientHandshakeWithAddons(&wrapped, uuid, "example.com:443", "tcp", nil); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plain.Bytes(), wrapped.Bytes()) {
		t.Fatalf("ClientHandshake output differs from ClientHandshakeWithAddons nil output")
	}
}

func TestClientHandshakeWithAddonsEncodesRequest(t *testing.T) {
	uuid, err := ParseUUID("11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	addons := []byte(AddonFlowVision)

	var buf bytes.Buffer
	if err := ClientHandshakeWithAddons(&buf, uuid, "127.0.0.1:53", "udp", addons); err != nil {
		t.Fatal(err)
	}

	req, err := ReadRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if req.UUID != uuid {
		t.Fatalf("uuid mismatch: got %s want %s", req.UUID, uuid)
	}
	if !bytes.Equal(req.Addons, addons) {
		t.Fatalf("addons mismatch: got %q want %q", req.Addons, addons)
	}
	if req.Network != "udp" {
		t.Fatalf("network mismatch: got %q want udp", req.Network)
	}
	if req.Host != "127.0.0.1" || req.Port != 53 {
		t.Fatalf("target mismatch: got %s:%d", req.Host, req.Port)
	}
}
