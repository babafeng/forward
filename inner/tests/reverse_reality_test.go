package tests

import (
	"fmt"
	"strings"
	"testing"

	"forward/inner/config"
	"forward/inner/dialer"
	"forward/base/endpoint"
	"forward/inner/listener"
	rclient "forward/inner/reverse/client"
	"forward/base/utils/crypto"
)

func realityForwardEndpoint(t *testing.T) endpoint.Endpoint {
	t.Helper()

	uuid := crypto.GenerateUUID()
	if uuid == "" {
		uuid = "11111111-1111-1111-1111-111111111111"
	}
	_, pbk, err := crypto.GenerateX25519Keys()
	if err != nil {
		t.Fatalf("generate reality key failed: %v", err)
	}
	sid := crypto.GenerateShortID(4)

	raw := fmt.Sprintf(
		"reality://%s@example.com:443?pbk=%s&sid=%s&sni=swscan.apple.com&security=reality",
		uuid,
		pbk,
		sid,
	)
	ep, err := endpoint.Parse(raw)
	if err != nil {
		t.Fatalf("parse endpoint failed: %v", err)
	}
	return ep
}

func TestReverseListenerRealityRequiresBind(t *testing.T) {
	ep, err := endpoint.Parse("reality://user@:2333")
	if err != nil {
		t.Fatalf("parse endpoint failed: %v", err)
	}

	cfg := config.Config{
		Mode:   config.ModeReverseServer,
		Listen: ep,
		Logger: testLogger(),
	}

	_, err = listener.New(cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "bind=true") {
		t.Fatalf("expected bind error, got %v", err)
	}
}

func TestReverseListenerRealityRunner(t *testing.T) {
	uuid := crypto.GenerateUUID()
	if uuid == "" {
		uuid = "11111111-1111-1111-1111-111111111111"
	}
	raw := fmt.Sprintf("reality://%s@:2333?bind=true", uuid)
	ep, err := endpoint.Parse(raw)
	if err != nil {
		t.Fatalf("parse endpoint failed: %v", err)
	}

	cfg := config.Config{
		Mode:   config.ModeReverseServer,
		Listen: ep,
		Logger: testLogger(),
	}

	runner, err := listener.New(cfg, nil)
	if err != nil {
		t.Fatalf("reverse listener init failed: %v", err)
	}
	if runner == nil {
		t.Fatalf("reverse listener is nil")
	}
}

func TestDialerRealityAlias(t *testing.T) {
	ep := realityForwardEndpoint(t)

	cfg := config.Config{
		Forward: &ep,
	}

	d, err := dialer.New(cfg)
	if err != nil {
		t.Fatalf("dialer init failed: %v", err)
	}
	if d == nil {
		t.Fatalf("dialer is nil")
	}
}

func TestReverseClientRealityAlias(t *testing.T) {
	ep := realityForwardEndpoint(t)

	cfg := config.Config{
		Forward: &ep,
		Logger:  testLogger(),
	}

	runner, err := rclient.New(cfg)
	if err != nil {
		t.Fatalf("reverse client init failed: %v", err)
	}
	if runner == nil {
		t.Fatalf("reverse client runner is nil")
	}
}
