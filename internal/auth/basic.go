package auth

import "crypto/subtle"

type Authenticator interface {
	Check(user, pass string) bool
}

type None struct{}

func (None) Check(_, _ string) bool { return true }

type Basic struct {
	user string
	pass string
}

func NewBasic(user, pass string) *Basic {
	return &Basic{user: user, pass: pass}
}

func (b *Basic) Check(user, pass string) bool {
	userMatch := subtle.ConstantTimeCompare([]byte(b.user), []byte(user)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(b.pass), []byte(pass)) == 1
	return userMatch && passMatch
}

func FromUserPass(user, pass string) Authenticator {
	if user == "" && pass == "" {
		return None{}
	}
	return NewBasic(user, pass)
}
