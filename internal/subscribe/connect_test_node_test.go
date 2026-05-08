package subscribe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"forward/internal/chain"
)

func TestIsWarmupRound(t *testing.T) {
	if !isWarmupRound(0) {
		t.Fatal("round 0 should be warmup")
	}
	if isWarmupRound(warmupRounds) {
		t.Fatalf("round %d should be measured", warmupRounds)
	}
}

func TestNodeBestLatencyIgnoresWarmupRequest(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&requests, 1) == 1 {
			time.Sleep(500 * time.Millisecond)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	latency, err := testNodeBestLatency(context.Background(), chain.NewDefaultRoute(time.Second), server.URL)
	if err != nil {
		t.Fatalf("testNodeBestLatency error = %v", err)
	}

	if got := atomic.LoadInt32(&requests); got != testRounds {
		t.Fatalf("requests = %d, want %d", got, testRounds)
	}
	if latency >= 250*time.Millisecond {
		t.Fatalf("latency = %s, warmup request appears to be included", latency)
	}
}
