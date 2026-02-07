package tests

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	hyclient "github.com/apernet/hysteria/core/v2/client"
	hyserver "github.com/apernet/hysteria/core/v2/server"
	hyauth "github.com/apernet/hysteria/extras/v2/auth"
	hyobfs "github.com/apernet/hysteria/extras/v2/obfs"

	"forward/base/endpoint"
	"forward/internal/builder"
	"forward/internal/chain"
	"forward/internal/config"
	ctls "forward/internal/config/tls"
	internalhy2 "forward/internal/hysteria2"
	"forward/internal/router"
)

func TestHysteria2OutboundTCPAndUDP(t *testing.T) {
	auth := "hysteria2-outbound-token"
	serverAddr, stop := startNativeHysteria2Server(t, auth, "")
	defer stop()

	tcpBackend, stopTCP := startTCPEchoServer(t)
	defer stopTCP()
	udpBackend, stopUDP := startUDPEchoServer(t)
	defer stopUDP()

	ep := mustParseEndpoint(t, fmt.Sprintf("hysteria2://%s@%s?insecure=1&peer=peer.example.com", auth, serverAddr))
	route := buildRoute(t, ep)

	tcpConn := dialWithRetry(t, route, "tcp", tcpBackend)
	defer tcpConn.Close()
	assertEcho(t, tcpConn, []byte("hy2-outbound-tcp"))

	udpConn := dialWithRetry(t, route, "udp", udpBackend)
	defer udpConn.Close()
	assertUDPEcho(t, udpConn, []byte("hy2-outbound-udp"))
}

func TestHysteria2OutboundInvalidObfs(t *testing.T) {
	ep := mustParseEndpoint(t, "hysteria2://token@127.0.0.1:443?obfs=unknown")
	cfg := config.Config{
		Logger:           testLogger(),
		DialTimeout:      3 * time.Second,
		HandshakeTimeout: 3 * time.Second,
		Insecure:         true,
	}
	config.ApplyDefaults(&cfg)

	_, err := builder.BuildRoute(cfg, []endpoint.Endpoint{ep})
	if err == nil {
		t.Fatalf("BuildRoute should fail for unsupported obfs type")
	}
}

func TestHysteria2InboundTCPAndUDP(t *testing.T) {
	auth := "hysteria2-inbound-token"
	serverAddr, stop := startInternalHysteria2Server(t, auth, "")
	defer stop()

	tcpBackend, stopTCP := startTCPEchoServer(t)
	defer stopTCP()
	udpBackend, stopUDP := startUDPEchoServer(t)
	defer stopUDP()

	client := mustNewHysteria2Client(t, serverAddr, auth, "")
	defer client.Close()

	tcpConn, err := client.TCP(tcpBackend)
	if err != nil {
		t.Fatalf("hy2 client tcp dial: %v", err)
	}
	defer tcpConn.Close()
	assertEcho(t, tcpConn, []byte("hy2-inbound-tcp"))

	udpConn, err := client.UDP()
	if err != nil {
		t.Fatalf("hy2 client udp dial: %v", err)
	}
	defer udpConn.Close()

	udpPayload := []byte("hy2-inbound-udp")
	if err := udpConn.Send(udpPayload, udpBackend); err != nil {
		t.Fatalf("hy2 udp send: %v", err)
	}
	rData, rAddr, err := receiveUDPWithTimeout(udpConn, 3*time.Second)
	if err != nil {
		t.Fatalf("hy2 udp receive: %v", err)
	}
	if string(rData) != string(udpPayload) {
		t.Fatalf("unexpected udp echo: got %q, want %q", string(rData), string(udpPayload))
	}
	if rAddr != udpBackend {
		t.Fatalf("unexpected udp source: got %q, want %q", rAddr, udpBackend)
	}
}

func receiveUDPWithTimeout(conn hyclient.HyUDPConn, timeout time.Duration) ([]byte, string, error) {
	type result struct {
		data []byte
		addr string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, addr, err := conn.Receive()
		ch <- result{data: data, addr: addr, err: err}
	}()
	select {
	case r := <-ch:
		return r.data, r.addr, r.err
	case <-time.After(timeout):
		return nil, "", fmt.Errorf("receive timeout")
	}
}

func startNativeHysteria2Server(t *testing.T, auth string, obfsPassword string) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen hy2 udp: %v", err)
	}
	listenAddr := pc.LocalAddr().String()

	if obfsPassword != "" {
		ob, err := hyobfs.NewSalamanderObfuscator([]byte(obfsPassword))
		if err != nil {
			_ = pc.Close()
			t.Fatalf("new salamander obfs: %v", err)
		}
		pc = hyobfs.WrapPacketConn(pc, ob)
	}

	tlsCfg := testHysteria2ServerTLSConfig(t)
	serverCfg := &hyserver.Config{
		TLSConfig: tlsCfg,
		Conn:      pc,
		Authenticator: &hyauth.PasswordAuthenticator{
			Password: auth,
		},
	}
	s, err := hyserver.NewServer(serverCfg)
	if err != nil {
		_ = pc.Close()
		t.Fatalf("new hy2 server: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Serve()
	}()

	stop := func() {
		_ = s.Close()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
			t.Log("native hy2 server shutdown timed out")
		}
	}
	return listenAddr, stop
}

func startInternalHysteria2Server(t *testing.T, auth string, obfsPassword string) (string, func()) {
	t.Helper()
	port := freeUDPPort(t)
	query := url.Values{}
	if obfsPassword != "" {
		query.Set("obfs", "salamander")
		query.Set("obfs-password", obfsPassword)
	}

	var user *url.Userinfo
	if auth != "" {
		user = url.User(auth)
	}
	ep := buildEndpoint(t, "hysteria2", "127.0.0.1", port, user, query)

	cfg := config.Config{
		Listen:         ep,
		Logger:         testLogger(),
		DialTimeout:    3 * time.Second,
		UDPIdleTimeout: 10 * time.Second,
	}
	config.ApplyDefaults(&cfg)

	rt := router.NewStatic(chain.NewRoute())
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- internalhy2.Serve(ctx, cfg, rt)
	}()

	// Give listener a moment to bind before clients connect.
	time.Sleep(150 * time.Millisecond)

	stop := func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Logf("internal hy2 server stopped with error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Log("internal hy2 server shutdown timed out")
		}
	}
	return ep.Address(), stop
}

func mustNewHysteria2Client(t *testing.T, serverAddr, auth string, obfsPassword string) hyclient.Client {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatalf("resolve hy2 server addr %q: %v", serverAddr, err)
	}

	cfg := &hyclient.Config{
		ServerAddr: udpAddr,
		Auth:       auth,
		TLSConfig: hyclient.TLSConfig{
			InsecureSkipVerify: true,
		},
	}

	if obfsPassword != "" {
		ob, err := hyobfs.NewSalamanderObfuscator([]byte(obfsPassword))
		if err != nil {
			t.Fatalf("new salamander obfs: %v", err)
		}
		cfg.ConnFactory = &testObfsConnFactory{ob: ob}
	}

	client, _, err := hyclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("new hy2 client: %v", err)
	}
	return client
}

func testHysteria2ServerTLSConfig(t *testing.T) hyserver.TLSConfig {
	t.Helper()
	ep := mustParseEndpoint(t, "hysteria2://127.0.0.1:443")
	cfg := config.Config{Listen: ep, Logger: testLogger()}
	config.ApplyDefaults(&cfg)
	tlsCfg, err := ctls.ServerConfig(cfg, ctls.ServerOptions{})
	if err != nil {
		t.Fatalf("build test tls config: %v", err)
	}
	return hyserver.TLSConfig{
		Certificates:   tlsCfg.Certificates,
		GetCertificate: tlsCfg.GetCertificate,
		ClientCAs:      tlsCfg.ClientCAs,
	}
}

type testObfsConnFactory struct {
	ob hyobfs.Obfuscator
}

func (f *testObfsConnFactory) New(net.Addr) (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}
	if f.ob == nil {
		return pc, nil
	}
	return hyobfs.WrapPacketConn(pc, f.ob), nil
}
