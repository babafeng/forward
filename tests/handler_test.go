package tests

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"forward/inner/config"
	"forward/inner/endpoint"
	forwardhttp "forward/inner/handler/http"
	"forward/inner/logging"
)

type mockDialer struct{}

func (m *mockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, net.UnknownNetworkError("mock dial error")
}

func TestHandler_Camouflage(t *testing.T) {
	cfg := config.Config{
		Logger: logging.New(logging.Options{Level: logging.LevelError}),
		Listen: endpoint.Endpoint{
			Scheme: "http",
			User:   nil, // No auth enabled initially
		},
	}

	h := forwardhttp.New(cfg, &mockDialer{})

	tests := []struct {
		name           string
		method         string
		target         string // Request URI
		header         http.Header
		expectedStatus int
		expectedTitle  string
	}{
		{
			name:           "Probe GET /",
			method:         "GET",
			target:         "/",
			expectedStatus: http.StatusForbidden,
			expectedTitle:  "403 Forbidden",
		},
		{
			name:           "Probe HEAD /",
			method:         "HEAD",
			target:         "/",
			expectedStatus: http.StatusForbidden,
			expectedTitle:  "403 Forbidden",
		},
		{
			name:           "Probe POST /",
			method:         "POST",
			target:         "/",
			expectedStatus: http.StatusForbidden,
			expectedTitle:  "403 Forbidden",
		},
		{
			name:           "Probe GET / (Origin Form)",
			method:         "GET",
			target:         "http://127.0.0.1:8080/",
			header:         nil,
			expectedStatus: http.StatusForbidden,
			expectedTitle:  "403 Forbidden",
		},
		{
			name:           "Proxy Request (Absolute URI)",
			method:         "GET",
			target:         "http://example.com/",
			expectedStatus: http.StatusForbidden,
			expectedTitle:  "403 Forbidden",
		},
		{
			name:           "CONNECT Request",
			method:         "CONNECT",
			target:         "example.com:443",
			expectedStatus: http.StatusForbidden,
			expectedTitle:  "403 Forbidden",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.target, nil)
			w := httptest.NewRecorder()

			if tt.expectedTitle == "403 Forbidden" {
				r.URL.Scheme = ""
				r.URL.Host = ""
				r.RequestURI = tt.target
			}

			if tt.method == "CONNECT" {
				r.URL.Scheme = ""
			}

			h.ServeHTTP(w, r)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
			if w.Code == http.StatusForbidden {
				body := w.Body.String()
				if !strings.Contains(body, "<html>") || !strings.Contains(body, tt.expectedTitle) {
					t.Errorf("expected HTML body with title/content '%s', got '%s'", tt.expectedTitle, body)
				}
				if !strings.Contains(body, "<center>nginx</center>") {
					t.Errorf("expected nginx signature in body, got '%s'", body)
				}
			}
		})
	}
}

func TestHandler_Camouflage_WithAuth(t *testing.T) {
	user := "user"
	pass := "pass"
	cfg := config.Config{
		Logger: logging.New(logging.Options{Level: logging.LevelError}),
		Listen: endpoint.Endpoint{
			Scheme: "http",
			User:   url.UserPassword(user, pass),
		},
	}

	h := forwardhttp.New(cfg, &mockDialer{})

	// 1. Probe request -> 403
	req := httptest.NewRequest("GET", "/", nil)
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.RequestURI = "/"

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Probe with auth enabled: expected 403, got %d", w.Code)
	}

	// 2. Normal Proxy Request without Auth -> 403
	req2 := httptest.NewRequest("GET", "http://example.com/", nil)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Errorf("Proxy with auth enabled (no creds): expected 403, got %d", w2.Code)
	}

	// Check Realm
	authHeader := w2.Header().Get("Proxy-Authenticate")
	if !strings.Contains(authHeader, `realm="Authorization Required"`) {
		t.Errorf("expected generic realm 'Authorization Required', got '%s'", authHeader)
	}

	// 3. Normal Proxy Request WITH Auth -> Forbidden (Mock Dial failure treated as Forbidden)
	req3 := httptest.NewRequest("GET", "http://example.com/", nil)
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	req3.Header.Set("Proxy-Authorization", auth)
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, req3)

	if w3.Code != http.StatusForbidden {
		t.Errorf("Proxy with auth enabled (valid creds): expected 403 (Mock Dial Error), got %d", w3.Code)
	}
}
