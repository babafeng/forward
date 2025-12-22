package utils

import (
	"crypto/subtle"
	"errors"
	"strings"
)

// Auth handles user authentication
type Auth struct {
	User string
	Pass string
}

// NewAuth creates a new Auth instance from a user:pass string
func NewAuth(authStr string) (*Auth, error) {
	parts := strings.SplitN(authStr, ":", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid auth format, expected user:pass")
	}
	return &Auth{
		User: parts[0],
		Pass: parts[1],
	}, nil
}

// Validate checks if the provided user and pass match the configured auth
func (a *Auth) Validate(user, pass string) bool {
	userMatch := subtle.ConstantTimeCompare([]byte(a.User), []byte(user)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(a.Pass), []byte(pass)) == 1
	return userMatch && passMatch
}
