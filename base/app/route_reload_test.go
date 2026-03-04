package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"forward/base/logging"
)

func TestInitRouteStoreAndHotReloadReloadsRouteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route.ini")
	writeRouteINI(t, path, "P1")

	cfg, err := parseRouteConfig(path)
	if err != nil {
		t.Fatalf("parse route config: %v", err)
	}
	cfg.RoutePath = path
	cfg.Logger = logging.New(logging.Options{Level: logging.LevelError})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := initRouteStoreAndHotReload(ctx, &cfg); err != nil {
		t.Fatalf("init route reload: %v", err)
	}
	if cfg.RouteStore == nil {
		t.Fatalf("route store should be initialized")
	}

	waitFor(t, 2*time.Second, func() bool {
		decision, err := cfg.RouteStore.Decide(context.Background(), "www.example.com:443")
		return err == nil && decision.Via == "P1"
	}, "initial decision not ready")

	writeRouteINI(t, path, "P2")

	waitFor(t, 5*time.Second, func() bool {
		decision, err := cfg.RouteStore.Decide(context.Background(), "www.example.com:443")
		return err == nil && decision.Via == "P2" && cfg.RouteStore.Version() >= 1
	}, "route decision was not reloaded to P2")
}

func TestInitRouteStoreAndHotReloadKeepsOldRouteOnParseError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route.ini")
	writeRouteINI(t, path, "P1")

	cfg, err := parseRouteConfig(path)
	if err != nil {
		t.Fatalf("parse route config: %v", err)
	}
	cfg.RoutePath = path
	cfg.Logger = logging.New(logging.Options{Level: logging.LevelError})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := initRouteStoreAndHotReload(ctx, &cfg); err != nil {
		t.Fatalf("init route reload: %v", err)
	}

	waitFor(t, 2*time.Second, func() bool {
		decision, err := cfg.RouteStore.Decide(context.Background(), "www.example.com:443")
		return err == nil && decision.Via == "P1"
	}, "initial decision not ready")

	prevVersion := cfg.RouteStore.Version()
	writeBrokenRouteINI(t, path)

	time.Sleep(1500 * time.Millisecond)

	decision, err := cfg.RouteStore.Decide(context.Background(), "www.example.com:443")
	if err != nil {
		t.Fatalf("unexpected decision error after broken reload: %v", err)
	}
	if decision.Via != "P1" {
		t.Fatalf("decision via = %s, want P1", decision.Via)
	}
	if got := cfg.RouteStore.Version(); got != prevVersion {
		t.Fatalf("route version = %d, want %d", got, prevVersion)
	}
}

func waitFor(t *testing.T, timeout time.Duration, fn func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal(msg)
}

func writeRouteINI(t *testing.T, path, proxy string) {
	t.Helper()
	content := "[General]\n" +
		"listen = http://127.0.0.1:1080\n\n" +
		"[Proxy]\n" +
		"P1 = socks5://127.0.0.1:1081\n" +
		"P2 = socks5://127.0.0.1:1082\n\n" +
		"[Rule]\n" +
		"DOMAIN-SUFFIX,example.com," + proxy + "\n" +
		"FINAL,DIRECT\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write route ini: %v", err)
	}
}

func writeBrokenRouteINI(t *testing.T, path string) {
	t.Helper()
	content := "[General]\n" +
		"listen =\n\n" +
		"[Proxy]\n" +
		"P1 = socks5://127.0.0.1:1081\n\n" +
		"[Rule]\n" +
		"DOMAIN-SUFFIX,example.com,P2\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write broken route ini: %v", err)
	}
}
