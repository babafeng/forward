package hysteria2

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	hyclient "github.com/apernet/hysteria/core/v2/client"
	hyobfs "github.com/apernet/hysteria/extras/v2/obfs"

	"forward/internal/dialer"
	"forward/internal/metadata"
	"forward/internal/registry"
)

const (
	mdKeyAddress      = "address"
	mdKeyAuth         = "auth"
	mdKeySNI          = "sni"
	mdKeyALPN         = "alpn"
	mdKeyInsecure     = "insecure"
	mdKeyPinSHA256    = "pinsha256"
	mdKeyOBFS         = "obfs"
	mdKeyOBFSPassword = "obfs_password"
	mdKeyCA           = "ca"
)

func init() {
	_ = registry.DialerRegistry().Register("hysteria2", NewDialer)
	_ = registry.DialerRegistry().Register("hy2", NewDialer)
}

type dialerConfig struct {
	address      string
	auth         string
	sni          string
	insecure     bool
	pinSHA256    string
	alpn         string
	obfs         string
	obfsPassword string
	caFile       string
}

type Dialer struct {
	options dialer.Options

	mu     sync.RWMutex
	cfg    dialerConfig
	client hyclient.Client
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &Dialer{options: options}
}

func (d *Dialer) Init(md metadata.Metadata) error {
	if md == nil {
		return errors.New("hysteria2 dialer requires metadata")
	}

	cfg := dialerConfig{
		address:      strings.TrimSpace(getString(md.Get(mdKeyAddress))),
		auth:         getString(md.Get(mdKeyAuth)),
		sni:          strings.TrimSpace(getString(md.Get(mdKeySNI))),
		alpn:         strings.TrimSpace(getString(md.Get(mdKeyALPN))),
		insecure:     getBool(md.Get(mdKeyInsecure)),
		pinSHA256:    normalizeCertHash(getString(md.Get(mdKeyPinSHA256))),
		obfs:         strings.ToLower(strings.TrimSpace(getString(md.Get(mdKeyOBFS)))),
		obfsPassword: getString(md.Get(mdKeyOBFSPassword)),
		caFile:       strings.TrimSpace(getString(md.Get(mdKeyCA))),
	}
	if cfg.address == "" {
		return errors.New("hysteria2 dialer requires server address")
	}
	if cfg.pinSHA256 != "" {
		if len(cfg.pinSHA256) != sha256.Size*2 {
			return errors.New("hysteria2 pinSHA256 must be a 64-character hex string")
		}
		if _, err := hex.DecodeString(cfg.pinSHA256); err != nil {
			return fmt.Errorf("hysteria2 invalid pinSHA256: %w", err)
		}
	}
	switch cfg.obfs {
	case "", "plain", "salamander":
	default:
		return fmt.Errorf("hysteria2 unsupported obfs type: %s", cfg.obfs)
	}
	if cfg.obfs == "salamander" && cfg.obfsPassword == "" {
		return errors.New("hysteria2 obfs-password is required for salamander")
	}
	if cfg.alpn != "" && d.options.Logger != nil {
		d.options.Logger.Warn("Hysteria2 dialer ignores ALPN setting: %s", cfg.alpn)
	}

	client, err := hyclient.NewReconnectableClient(func() (*hyclient.Config, error) {
		return buildClientConfig(cfg)
	}, nil, true)
	if err != nil {
		return err
	}

	d.mu.Lock()
	d.cfg = cfg
	d.client = client
	d.mu.Unlock()
	return nil
}

func (d *Dialer) Dial(ctx context.Context, addr string, _ ...dialer.DialOption) (net.Conn, error) {
	d.mu.RLock()
	client := d.client
	d.mu.RUnlock()
	if client == nil {
		return nil, errors.New("hysteria2 dialer is not initialized")
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if d.options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.options.Timeout)
		defer cancel()
	}

	raddr, _ := net.ResolveUDPAddr("udp", addr)
	return &clientProviderConn{
		client: client,
		local:  &net.UDPAddr{},
		remote: raddr,
	}, nil
}

type clientProviderConn struct {
	client hyclient.Client
	local  net.Addr
	remote net.Addr
}

func (c *clientProviderConn) HYClient() hyclient.Client { return c.client }
func (c *clientProviderConn) Read([]byte) (int, error)  { return 0, net.ErrClosed }
func (c *clientProviderConn) Write([]byte) (int, error) { return 0, net.ErrClosed }
func (c *clientProviderConn) Close() error              { return nil }
func (c *clientProviderConn) LocalAddr() net.Addr       { return c.local }
func (c *clientProviderConn) RemoteAddr() net.Addr      { return c.remote }
func (c *clientProviderConn) SetDeadline(time.Time) error {
	return nil
}
func (c *clientProviderConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *clientProviderConn) SetWriteDeadline(time.Time) error {
	return nil
}

func buildClientConfig(cfg dialerConfig) (*hyclient.Config, error) {
	serverAddr := cfg.address
	if _, _, err := net.SplitHostPort(serverAddr); err != nil {
		serverAddr = net.JoinHostPort(serverAddr, "443")
	}
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve hysteria2 server: %w", err)
	}

	host, _, _ := net.SplitHostPort(serverAddr)
	host = strings.Trim(host, "[]")

	c := &hyclient.Config{
		ServerAddr: addr,
		Auth:       cfg.auth,
		FastOpen:   true,
	}
	c.TLSConfig.InsecureSkipVerify = cfg.insecure
	c.TLSConfig.ServerName = host
	if cfg.sni != "" {
		c.TLSConfig.ServerName = cfg.sni
	}
	if cfg.pinSHA256 != "" {
		pin := cfg.pinSHA256
		c.TLSConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("hysteria2 pin verify: no peer certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if hex.EncodeToString(sum[:]) != pin {
				return errors.New("hysteria2 pin verify: certificate mismatch")
			}
			return nil
		}
	}
	if cfg.caFile != "" {
		pemBytes, err := os.ReadFile(cfg.caFile)
		if err != nil {
			return nil, fmt.Errorf("read hysteria2 ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("parse hysteria2 ca pem failed")
		}
		c.TLSConfig.RootCAs = pool
	}

	switch cfg.obfs {
	case "", "plain":
	case "salamander":
		ob, err := hyobfs.NewSalamanderObfuscator([]byte(cfg.obfsPassword))
		if err != nil {
			return nil, fmt.Errorf("init hysteria2 salamander obfs: %w", err)
		}
		c.ConnFactory = &obfsConnFactory{
			base: udpConnFactory{},
			obfs: ob,
		}
	}

	return c, nil
}

type udpConnFactory struct{}

func (udpConnFactory) New(net.Addr) (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

type obfsConnFactory struct {
	base hyclient.ConnFactory
	obfs hyobfs.Obfuscator
}

func (f *obfsConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	pc, err := f.base.New(addr)
	if err != nil {
		return nil, err
	}
	return hyobfs.WrapPacketConn(pc, f.obfs), nil
}

func getString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return ""
	}
}

func getBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		t = strings.TrimSpace(strings.ToLower(t))
		return t == "1" || t == "true" || t == "yes" || t == "on"
	default:
		return false
	}
}

func normalizeCertHash(hash string) string {
	r := strings.ToLower(strings.TrimSpace(hash))
	r = strings.ReplaceAll(r, ":", "")
	r = strings.ReplaceAll(r, "-", "")
	return r
}
