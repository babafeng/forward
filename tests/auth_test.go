package tests

import (
	"testing"

	"forward/internal/auth"
)

func TestBasicAuthenticator(t *testing.T) {
	a := auth.FromUserPass("admin", "secret")

	tests := []struct {
		name string
		user string
		pass string
		want bool
	}{
		{"correct credentials", "admin", "secret", true},
		{"wrong password", "admin", "wrong", false},
		{"wrong username", "user", "secret", false},
		{"empty credentials", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.Check(tt.user, tt.pass); got != tt.want {
				t.Errorf("Check(%q, %q) = %v, want %v", tt.user, tt.pass, got, tt.want)
			}
		})
	}
}

func TestNilAuthenticator(t *testing.T) {
	a := auth.FromUserPass("", "")

	// nil authenticator should allow all
	if a != nil && !a.Check("any", "thing") {
		t.Error("nil authenticator should allow any credentials")
	}
}
