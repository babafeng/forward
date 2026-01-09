package reverse

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

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

	_ = conn.SetReadDeadline(time.Now().Add(config.DefaultHandshakeTimeout))

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

	// Check Socks5 Bind
	host, port, isUDP, err := rproto.Socks5ServerBind(br, bw, authFn)
	if err != nil {
		s.log.Error("Reverse server socks5 bind error: %v", err)
		return
	}

	if host == "" {
		host = "0.0.0.0"
	}
	bindAddr := net.JoinHostPort(host, strconv.Itoa(port))

	var ln net.Listener
	var udpLn *net.UDPConn
	var network string

	if isUDP {
		network = "udp"
		uaddr, err := net.ResolveUDPAddr("udp", bindAddr)
		if err != nil {
			s.log.Error("Reverse server resolve udp %s: %v", bindAddr, err)
			return
		}
		udpLn, err = net.ListenUDP("udp", uaddr)
		if err != nil {
			s.log.Error("Reverse server listen udp %s error: %v", bindAddr, err)
			return
		}
		defer udpLn.Close()
	} else {
		network = "tcp"
		ln, err = net.Listen("tcp", bindAddr)
		if err != nil {
			s.log.Error("Reverse server listen tcp %s error: %v", bindAddr, err)
			return
		}
		defer ln.Close()
	}

	if err := rproto.WriteBindSuccess(bw, host, port); err != nil {
		s.log.Error("Reverse server write bind reply error: %v", err)
		return
	}

	s.log.Info("Reverse server bound %s (%s), bridging to client %s", bindAddr, network, conn.RemoteAddr())

	// Generate Session ID
	sidBuf := make([]byte, 8)
	if _, err := rand.Read(sidBuf); err != nil {
		s.log.Error("Reverse server init error: %v", err)
		return
	}
	sid := hex.EncodeToString(sidBuf)

	conf := yamux.DefaultConfig()
	conf.KeepAliveInterval = 10 * time.Second
	conf.LogOutput = nil
	conf.Logger = log.New(s.log.Writer(logging.LevelDebug), fmt.Sprintf("[yamux][%s] ", sid), 0)

	_ = conn.SetReadDeadline(time.Time{})

	session, err := yamux.Client(conn, conf)
	if err != nil {
		s.log.Error("[%s] Reverse server yamux error: %v", sid, err)
		return
	}
	defer session.Close()

	go func() {
		select {
		case <-ctx.Done():
		case <-session.CloseChan():
		}
		if ln != nil {
			_ = ln.Close()
		}
		if udpLn != nil {
			_ = udpLn.Close()
		}
		_ = session.Close()
		_ = conn.Close()
	}()

	s.log.Info("[%s] Reverse session established for %s", sid, bindAddr)

	if isUDP {
		s.handleBoundUDP(ctx, session, udpLn, sid)
	} else {
		for {
			lc, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				s.log.Error("[%s] Reverse server accept bound error: %v", sid, err)
				return
			}
			go s.handleBoundConn(ctx, session, lc, sid)
		}
	}
}

func (s *Server) handleBoundConn(ctx context.Context, session *yamux.Session, clientConn net.Conn, sid string) {
	defer clientConn.Close()

	src := clientConn.RemoteAddr().String()
	// clientConn.LocalAddr is 'bound' addr
	bound := clientConn.LocalAddr().String()
	// session.RemoteAddr is the Client's addr (tunnel end)
	tunnelRemote := session.RemoteAddr().String()

	s.log.Info("[%s] Forward Reverse Client Received connection %s --> %s --> %s", sid, src, bound, tunnelRemote)

	stream, err := session.Open()
	if err != nil {
		s.log.Error("[%s] Reverse server open stream error: %v", sid, err)
		return
	}
	defer stream.Close()

	dst := stream.RemoteAddr().String()
	s.log.Debug("[%s] Reverse TCP Connected to upstream %s --> %s", sid, src, dst)

	bytes, dur, err := inet.Bidirectional(ctx, clientConn, stream)
	if err != nil && ctx.Err() == nil {
		s.log.Error("[%s] Reverse server transfer error: %v", sid, err)
	}
	s.log.Debug("[%s] Reverse TCP Closed connection %s --> %s transferred %d bytes in %s", sid, src, dst, bytes, dur)
}

func (s *Server) handleBoundUDP(ctx context.Context, session *yamux.Session, conn *net.UDPConn, sid string) {
	type udpSession struct {
		stream   net.Conn
		ps       *inet.PacketStream
		lastSeen time.Time
	}

	activeSessions := make(map[string]*udpSession)
	idleTimeout := s.cfg.UDPIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = config.DefaultUDPIdleTimeout
	}

	pkt := make([]byte, 64*1024)
	bound := conn.LocalAddr().String()
	tunnelRemote := session.RemoteAddr().String()

	cleanupIdle := func() {
		now := time.Now()
		for k, sess := range activeSessions {
			if now.Sub(sess.lastSeen) > idleTimeout {
				_ = sess.stream.Close()
				delete(activeSessions, k)
				s.log.Debug("[%s] Reverse UDP session %s idle timeout", sid, k)
			}
		}
	}

	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFromUDP(pkt)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				cleanupIdle()
				continue
			}
			s.log.Error("[%s] Reverse UDP Read error: %v", sid, err)
			return
		}

		srcKey := src.String()
		sess, ok := activeSessions[srcKey]
		if !ok {
			if len(activeSessions) >= config.DefaultMaxUDPSessions {
				cleanupIdle()
				if len(activeSessions) >= config.DefaultMaxUDPSessions {
					s.log.Warn("[%s] Reverse UDP max sessions reached, dropping packet from %s", sid, srcKey)
					continue
				}
			}

			s.log.Info("[%s] Forward Reverse Client Received connection %s --> %s --> %s", sid, srcKey, bound, tunnelRemote)

			stream, err := session.Open()
			if err != nil {
				s.log.Error("[%s] Reverse UDP Open stream error: %v", sid, err)
				continue
			}

			ps := inet.NewPacketStream(stream)
			sess = &udpSession{
				stream:   stream,
				ps:       ps,
				lastSeen: time.Now(),
			}
			activeSessions[srcKey] = sess

			go func(uSess *udpSession, addr *net.UDPAddr) {
				defer uSess.stream.Close()
				buf := make([]byte, 64*1024)
				for {
					_ = uSess.stream.SetReadDeadline(time.Now().Add(idleTimeout))
					n, err := uSess.ps.Read(buf)
					if err != nil {
						return
					}
					if _, err := conn.WriteToUDP(buf[:n], addr); err != nil {
						return
					}
				}
			}(sess, src)
		} else {
			sess.lastSeen = time.Now()
		}

		if _, err := sess.ps.Write(pkt[:n]); err != nil {
			s.log.Error("[%s] Reverse UDP Write to stream error: %v", sid, err)
			sess.stream.Close()
			delete(activeSessions, srcKey)
		}
	}
}
