package chain

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTestNodeHTTP204_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	rt := &directRoute{}
	latency, err := testNodeHTTP204(rt, srv.URL)
	if err != nil {
		t.Fatalf("testNodeHTTP204 returned error: %v", err)
	}
	if latency <= 0 {
		t.Fatalf("latency = %v, want > 0", latency)
	}
}

func TestTestNodeHTTP204_StatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	rt := &directRoute{}
	_, err := testNodeHTTP204(rt, srv.URL)
	if err == nil {
		t.Fatal("testNodeHTTP204 should return error for 403 status")
	}
}

// directRoute is a minimal Route implementation that dials directly without proxy.
type directRoute struct{}

func (r *directRoute) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (r *directRoute) Nodes() []*Node { return nil }
