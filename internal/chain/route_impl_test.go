package chain

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"forward/base/logging"
	ictx "forward/internal/ctx"
)

func TestDefaultRouteInfoLogUsesDirectFormat(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	var out bytes.Buffer
	logger := logging.New(logging.Options{
		Level: logging.LevelInfo,
		Out:   &out,
		Err:   &out,
	})
	ctx := ictx.ContextWithTrace(context.Background(), &ictx.Trace{
		Src:    "192.168.1.224:57108",
		Local:  "1.2.3.4:443",
		Logger: logger,
	})

	rt := NewDefaultRoute(2 * time.Second)
	conn, err := rt.Dial(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
	<-done

	logs := out.String()
	if !strings.Contains(logs, "192.168.1.224:57108 -> TCP "+ln.Addr().String()+" --> DIRECT") {
		t.Fatalf("direct info log missing expected format, got: %s", logs)
	}
	if strings.Contains(logs, "1.2.3.4:443 -> TCP") {
		t.Fatalf("direct info log should not include local address, got: %s", logs)
	}
}
