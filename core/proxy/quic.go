package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"go-forward/core/utils"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func StartQUIC(addr string, forwardURL string, baseOpts *utils.ServerOptions) {
	tlsConfig := baseOpts.TLSConfig
	auth := baseOpts.Auth
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, http3.NextProtoH3)

	handler := &ProxyHandler{
		ForwardURL: forwardURL,
		Auth:       auth,
	}

	server := &http3.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	utils.Info("[Proxy] [QUIC] Listening on %s", addr)
	if err := server.ListenAndServe(); err != nil {
		utils.Error("[Proxy] [QUIC] Server error: %v", err)
	}
}

func quicConnect(proxyAddr string, targetAddr string, user *url.Userinfo) (net.Conn, error) {
	utils.Debug("[Proxy] [QUIC] Connecting to %s via %s", targetAddr, proxyAddr)
	tlsConf := &tls.Config{
		InsecureSkipVerify: utils.GetInsecure(),
		NextProtos:         []string{http3.NextProtoH3},
	}

	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		proxyAddr = net.JoinHostPort(proxyAddr, "443") // 默认端口
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	qConn, err := quic.DialAddr(ctx, proxyAddr, tlsConf, nil)
	if err != nil {
		utils.Error("[Proxy] [QUIC] Dial failed to %s: %v", proxyAddr, err)
		return nil, fmt.Errorf("quic dial failed: %v", err)
	}

	tr := &http3.Transport{}
	cc := tr.NewClientConn(qConn)

	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		qConn.CloseWithError(0, "")
		utils.Error("[Proxy] [QUIC] Open stream failed to %s: %v", proxyAddr, err)
		return nil, fmt.Errorf("open stream failed: %v", err)
	}

	reqURL := fmt.Sprintf("https://%s", proxyAddr)
	req, err := http.NewRequest(http.MethodConnect, reqURL, nil)
	if err != nil {
		str.Close()
		return nil, err
	}
	req.Host = targetAddr

	if user != nil {
		password, _ := user.Password()
		auth := user.Username() + ":" + password
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
		req.Header.Set("Proxy-Authorization", basicAuth)
	}

	start := time.Now()
	if err := str.SendRequestHeader(req); err != nil {
		str.Close()
		return nil, fmt.Errorf("send header failed: %v", err)
	}

	resp, err := str.ReadResponse()
	if err != nil {
		str.Close()
		return nil, fmt.Errorf("read response failed: %v", err)
	}
	utils.Info("[Proxy] [QUIC] response received: %s %s --> %s %d bytes %v",
		resp.Status, qConn.LocalAddr(), qConn.RemoteAddr(), resp.ContentLength, time.Since(start))

	if resp.StatusCode != 200 {
		str.Close()
		return nil, fmt.Errorf("responded with status: %s", resp.Status)
	}

	return &quicStreamConn{
		RequestStream: str,
		local:         qConn.LocalAddr(),
		remote:        qConn.RemoteAddr(),
	}, nil
}

// quicStreamConn 适配器
type quicStreamConn struct {
	*http3.RequestStream
	local  net.Addr
	remote net.Addr
}

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.local }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.remote }

func (c *quicStreamConn) SetWriteDeadline(t time.Time) error { return nil }
