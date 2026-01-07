package reverse

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/hashicorp/yamux"

	"forward/internal/auth"
	"forward/internal/config"
	inet "forward/internal/io/net"
	"forward/internal/logging"
	rproto "forward/internal/reverse/proto"
)

type Server struct {
	cfg         config.Config
	log         *logging.Logger
	auth        auth.Authenticator
	requireAuth bool
}

func NewServer(cfg config.Config) (*Server, error) {
	user, pass, ok := cfg.Listen.UserPass()
	return &Server{
		cfg:         cfg,
		log:         cfg.Logger,
		auth:        auth.FromUserPass(user, pass),
		requireAuth: ok && (user != "" || pass != ""),
	}, nil
}

func (s *Server) Handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	// Check first byte for SOCKS5 (0x05) vs HTTP Probe
	peek, err := br.Peek(1)
	if err != nil {
		s.log.Error("Reverse server peek error: %v", err)
		return
	}

	if peek[0] != 0x05 {
		title := config.CamouflagePageTitle
		body := fmt.Sprintf(config.CamouflagePageBody, title, title)
		resp := "HTTP/1.1 " + title + "\r\n" +
			"Content-Type: text/html\r\n" +
			"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			body
		_, _ = conn.Write([]byte(resp))
		return
	}

	var authFn func(string, string) bool
	if s.requireAuth {
		authFn = s.auth.Check
	}

	host, port, err := rproto.Socks5ServerBind(br, bw, authFn)
	if err != nil {
		s.log.Error("Reverse server socks5 bind error: %v", err)
		return
	}

	if host == "" {
		host = "0.0.0.0"
	}
	bindAddr := net.JoinHostPort(host, strconv.Itoa(port))
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		s.log.Error("Reverse server listen %s error: %v", bindAddr, err)
		return
	}
	defer ln.Close()

	if err := rproto.WriteBindSuccess(bw, host, port); err != nil {
		s.log.Error("Reverse server write bind reply error: %v", err)
		return
	}

	s.log.Info("Reverse server bound %s, bridging to client %s", bindAddr, conn.RemoteAddr())

	session, err := yamux.Client(conn, nil)
	if err != nil {
		s.log.Error("Reverse server yamux error: %v", err)
		return
	}
	defer session.Close()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
		_ = session.Close()
		_ = conn.Close()
	}()

	for {
		lc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.log.Error("Reverse server accept bound error: %v", err)
			return
		}
		go s.handleBoundConn(ctx, session, lc)
	}
}

func (s *Server) handleBoundConn(ctx context.Context, session *yamux.Session, clientConn net.Conn) {
	defer clientConn.Close()

	src := clientConn.RemoteAddr().String()
	s.log.Debug("Reverse TCP Received connection from %s", src)

	stream, err := session.Open()
	if err != nil {
		s.log.Error("Reverse server open stream error: %v", err)
		return
	}
	defer stream.Close()

	dst := stream.RemoteAddr().String()
	s.log.Debug("Reverse TCP Connected to upstream %s --> %s", src, dst)

	bytes, dur, err := inet.Bidirectional(ctx, clientConn, stream)
	if err != nil && ctx.Err() == nil {
		s.log.Error("Reverse server transfer error: %v", err)
	}
	s.log.Debug("Reverse TCP Closed connection %s --> %s transferred %d bytes in %s", src, dst, bytes, dur)
}
