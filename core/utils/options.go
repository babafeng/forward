package utils

import (
	"crypto/tls"
	"fmt"
	"net/url"

	"golang.org/x/crypto/ssh"
)

type ServerOptions struct {
	Auth           *Auth
	Addr           string
	Scheme         string
	SSHConfig      *ssh.ServerConfig
	TLSConfig      *tls.Config
	AuthorizedKeys []ssh.PublicKey
}

var tlsSchemes = map[string]struct{}{
	"http2":   {},
	"http3":   {},
	"https":   {},
	"http1.1": {},
	"tls":     {},
	"ssh":     {},
	"quic":    {},
}

func BuildServerOptions(listenURL string, defaultNextProtos []string) (*ServerOptions, error) {
	scheme, auth, addr := URLParse(listenURL)

	if _, ok := tlsSchemes[scheme]; !ok {
		return &ServerOptions{
			Auth:   auth,
			Addr:   addr,
			Scheme: scheme,
		}, nil
	}

	opts := &ServerOptions{}
	opts.Auth = auth
	opts.Addr = addr
	opts.Scheme = scheme

	params := url.Values{}
	params = ParseURLParams(listenURL)

	pubFile := params.Get("pub")
	if pubFile != "" {
		keys, err := LoadSSHAuthorizedKeys(pubFile)
		if err != nil {
			return nil, fmt.Errorf("[Reverse] [Server] Failed to load authorized keys: %w", err)
		}
		opts.AuthorizedKeys = keys
		Info("[Reverse] [Server] Loaded %d authorized keys from %s", len(keys), pubFile)
	}

	cert, err := &tls.Certificate{}, error(nil)

	certFile := params.Get("cert")
	keyFile := params.Get("key")
	if certFile != "" && keyFile != "" {
		cert, err = LoadCertificate(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("[Reverse] [Server] Failed to load certificate: %w", err)
		}
		Info("[Reverse] [Server] Loaded certificate from %s and %s", certFile, keyFile)
	} else {
		cert, err = GetCertificate()
		if err != nil {
			return nil, fmt.Errorf("[Reverse] [Server] Failed to generate certificate: %w", err)
		}
		Info("[Reverse] [Server] Generated self-signed certificate")
	}

	opts.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   defaultNextProtos,
	}

	if scheme == "ssh" {
		authenticator := NewSSHAuthenticator(auth, opts.AuthorizedKeys)
		sshcfg := &ssh.ServerConfig{
			NoClientAuth:      !authenticator.HasPassword() && !authenticator.HasAuthorizedKeys(),
			PasswordCallback:  authenticator.PasswordCallback,
			PublicKeyCallback: authenticator.PublicKeyCallback,
		}

		hostKey, err := GenerateSSHKey()
		if err != nil {
			return nil, fmt.Errorf("[Reverse] [Server] Failed to generate SSH host key: %w", err)
		}
		signer, err := ssh.NewSignerFromKey(hostKey)
		if err != nil {
			return nil, fmt.Errorf("[Reverse] [Server] Failed to create SSH host key signer: %w", err)
		}
		sshcfg.AddHostKey(signer)
		opts.SSHConfig = sshcfg
	}

	return opts, nil
}
