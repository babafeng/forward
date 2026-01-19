package tls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"forward/internal/config"
	"forward/inner/endpoint"

	"golang.org/x/crypto/ssh"
)

type ServerOptions struct {
	NextProtos []string
}

type ClientOptions struct {
	ServerName string
	NextProtos []string
}

func ServerConfig(cfg config.Config, opts ServerOptions) (*tls.Config, error) {
	certFile := strings.TrimSpace(cfg.Listen.Query.Get("cert"))
	keyFile := strings.TrimSpace(cfg.Listen.Query.Get("key"))

	var err error
	var cert tls.Certificate

	if certFile == "" || keyFile == "" {
		cert, err = getCertificate()
		if err != nil {
			cfg.Logger.Error("Failed to generate tls certificate: %v", err)
			return nil, fmt.Errorf("Failed to generate tls certificate: %w", err)
		}
		cfg.Logger.Warn("Generated self-signed tls certificate, just for development testing and debugging...")
	} else {
		cert, err = loadCertificate(certFile, keyFile)
		if err != nil {
			cfg.Logger.Error("Failed to load tls file: %v", err)
			return nil, fmt.Errorf("Failed to load tls file: %w", err)
		}
		cfg.Logger.Info("Loaded tls certificate successfully from files %s and %s", certFile, keyFile)
	}

	var clientCAs *x509.CertPool
	caFile := strings.TrimSpace(cfg.Listen.Query.Get("ca"))
	if caFile != "" {
		clientCAs, err = loadCA(caFile)
		if err != nil {
			cfg.Logger.Error("Failed to load self CA : %v", err)
			return nil, fmt.Errorf("Failed to load self CA: %w", err)
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   opts.NextProtos,
		ClientCAs:    clientCAs,
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}, nil
}

func ClientConfig(ep endpoint.Endpoint, insecure bool, opts ClientOptions) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: insecure,
		NextProtos:         opts.NextProtos,
		ServerName:         opts.ServerName,
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = ep.Host
	}
	caFile := strings.TrimSpace(ep.Query.Get("ca"))
	if caFile != "" {
		ca, err := loadCA(caFile)
		if err != nil {
			return nil, fmt.Errorf("load ca: %w", err)
		}
		tlsCfg.RootCAs = ca
	}
	if sni := strings.TrimSpace(ep.Query.Get("sni")); sni != "" {
		tlsCfg.ServerName = sni
	}
	return tlsCfg, nil
}

func loadCertificate(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

func loadCA(caFile string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("invalid CA pem")
	}
	return caCertPool, nil
}

func generateCert() (tls.Certificate, error) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Forward"},
			CommonName:   "Forward",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:    []string{"localhost"},
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func generateSSHKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

func loadSSHPrivateKey(keyFile, password string) (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	if password != "" {
		return ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(password))
	}
	return ssh.ParsePrivateKey(keyBytes)
}

func loadSSHAuthorizedKeys(pubFile string) ([]ssh.PublicKey, error) {
	pubBytes, err := os.ReadFile(pubFile)
	if err != nil {
		return nil, err
	}
	var keys []ssh.PublicKey
	for len(pubBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(pubBytes)
		if err != nil {
			break
		}
		if pubKey != nil {
			keys = append(keys, pubKey)
		}
		pubBytes = rest
	}
	return keys, nil
}

func sshKeysEqual(k1, k2 ssh.PublicKey) bool {
	return string(k1.Marshal()) == string(k2.Marshal())
}

var (
	cachedCert *tls.Certificate
	certOnce   sync.Once
)

func getCertificate() (tls.Certificate, error) {
	var err error
	certOnce.Do(func() {
		var c tls.Certificate
		c, err = generateCert()
		if err == nil {
			cachedCert = &c
		}
	})
	if cachedCert == nil {
		return tls.Certificate{}, err
	}
	return *cachedCert, nil
}
