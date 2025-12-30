package utils

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

type SSHAuthenticator struct {
	PasswordAuth   *Auth
	AuthorizedKeys []ssh.PublicKey
}

func NewSSHAuthenticator(password *Auth, keys []ssh.PublicKey) *SSHAuthenticator {
	return &SSHAuthenticator{
		PasswordAuth:   password,
		AuthorizedKeys: keys,
	}
}

func (a *SSHAuthenticator) HasPassword() bool {
	return a.PasswordAuth != nil
}

func (a *SSHAuthenticator) HasAuthorizedKeys() bool {
	return len(a.AuthorizedKeys) > 0
}

func (a *SSHAuthenticator) PasswordCallback(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	if a.PasswordAuth != nil {
		if a.PasswordAuth.Validate(c.User(), string(pass)) {
			return nil, nil
		}
		return nil, fmt.Errorf("password rejected for %q", c.User())
	}

	if a.HasAuthorizedKeys() {
		return nil, fmt.Errorf("password auth disabled when public keys are configured and no user/pass set")
	}

	return nil, nil
}

func (a *SSHAuthenticator) PublicKeyCallback(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	if a.PasswordAuth != nil && a.PasswordAuth.User != "" && a.PasswordAuth.User != c.User() {
		return nil, fmt.Errorf("unknown user %q", c.User())
	}

	if !a.HasAuthorizedKeys() {
		return nil, fmt.Errorf("no authorized keys configured")
	}

	for _, k := range a.AuthorizedKeys {
		if SSHKeysEqual(k, pubKey) {
			return nil, nil
		}
	}

	return nil, fmt.Errorf("unknown public key for %q", c.User())
}

func SSHHostKeyCallback() (ssh.HostKeyCallback, error) {
	if !GetInsecure() {
		return nil, fmt.Errorf("SSH host key verification is required but not configured. Use --insecure to skip verification")
	}
	return ssh.InsecureIgnoreHostKey(), nil
}
