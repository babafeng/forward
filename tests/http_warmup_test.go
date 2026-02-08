package tests

import (
	"context"
	"testing"

	handlerhttp "forward/internal/handler/http"
)

func TestWarmupInvalidURL(t *testing.T) {
	h := handlerhttp.NewHandler().(*handlerhttp.Handler)

	if _, err := h.Warmup(context.Background(), "ftp://example.com/file"); err == nil {
		t.Fatalf("expected error for invalid scheme")
	}

	if _, err := h.Warmup(context.Background(), "http:///missing-host"); err == nil {
		t.Fatalf("expected error for missing host")
	}
}
