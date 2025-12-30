package utils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	cachedCert *tls.Certificate
	certOnce   sync.Once
)

func GetCertificate() (*tls.Certificate, error) {
	var err error
	certOnce.Do(func() {
		var c tls.Certificate
		c, err = GenerateCert()
		if err == nil {
			cachedCert = &c
		}
	})
	if cachedCert == nil {
		return nil, err
	}
	return cachedCert, nil
}

func LoadCertificate(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func LoadCA(caFile string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return caCertPool, nil
}

func GenerateCert() (tls.Certificate, error) {
	// 生成自签名证书用于测试
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Forward"},
			CommonName:   "Forward",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 365),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
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

func GenerateSSHKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

func LoadSSHPrivateKey(keyFile, password string) (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	if password != "" {
		return ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(password))
	}
	return ssh.ParsePrivateKey(keyBytes)
}

func LoadSSHAuthorizedKeys(pubFile string) ([]ssh.PublicKey, error) {
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

func SSHKeysEqual(k1, k2 ssh.PublicKey) bool {
	return string(k1.Marshal()) == string(k2.Marshal())
}
