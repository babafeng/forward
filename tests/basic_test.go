package tests

import (
	"testing"

	"forward/base/auth"
)

func TestBasicAuth(t *testing.T) {
	tests := []struct {
		name      string
		authUser  string
		authPass  string
		checkUser string
		checkPass string
		want      bool
	}{
		{"correct", "admin", "secret", "admin", "secret", true},
		{"wrong_pass", "admin", "secret", "admin", "wrong", false},
		{"wrong_user", "admin", "secret", "other", "secret", false},
		{"both_wrong", "admin", "secret", "other", "wrong", false},
		{"empty_pass_correct", "admin", "", "admin", "", true},
		{"empty_pass_wrong", "admin", "", "admin", "any", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := auth.NewBasic(tt.authUser, tt.authPass)
			if got := a.Check(tt.checkUser, tt.checkPass); got != tt.want {
				t.Errorf("Check(%q, %q) = %v, want %v", tt.checkUser, tt.checkPass, got, tt.want)
			}
		})
	}
}

func TestNoneAuth(t *testing.T) {
	a := auth.None{}
	if !a.Check("any", "thing") {
		t.Error("None.Check() should always return true")
	}
}

func TestFromUserPass(t *testing.T) {
	tests := []struct {
		name     string
		user     string
		pass     string
		wantNone bool
	}{
		{"empty_both", "", "", true},
		{"user_only", "admin", "", false},
		{"pass_only", "", "secret", false},
		{"both", "admin", "secret", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := auth.FromUserPass(tt.user, tt.pass)
			_, isNone := a.(auth.None)
			if isNone != tt.wantNone {
				t.Errorf("FromUserPass() isNone = %v, want %v", isNone, tt.wantNone)
			}
		})
	}
}

func TestConstantTimeCompare(t *testing.T) {
	a := auth.NewBasic("admin", "secret")
	if !a.Check("admin", "secret") {
		t.Error("Should accept correct password")
	}
	if a.Check("admin", "wrong") {
		t.Error("Should reject wrong password")
	}
}

func TestEmptyCredentials(t *testing.T) {
	a := auth.NewBasic("", "")
	if !a.Check("", "") {
		t.Error("Empty auth should accept empty check")
	}
	if a.Check("any", "") {
		t.Error("Empty auth should reject non-empty user")
	}
}
