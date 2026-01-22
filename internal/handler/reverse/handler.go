package reverse

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/hashicorp/yamux"

	"forward/base/auth"
	inet "forward/base/io/net"
	"forward/base/pool"
	"forward/internal/config"
	"forward/internal/handler"
	"forward/internal/metadata"
	rev "forward/internal/reverse"
	rproto "forward/internal/reverse/proto"
)

const defaultReverseLimit = config.DefaultMaxConnections

type Handler struct {
	options          handler.Options
	auth             auth.Authenticator
	requireAuth      bool
	limit            chan struct{}
	handshakeTimeout time.Duration
	udpIdle          time.Duration
	maxUDPSessions   int
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	user := ""
	pass := ""
	if options.Auth != nil {
		user = options.Auth.Username()
		pass, _ = options.Auth.Password()
	}
	requireAuth := user != "" || pass != ""

	h := &Handler{
		options:          options,
		auth:             auth.FromUserPass(user, pass),
		requireAuth:      requireAuth,
		limit:            make(chan struct{}, defaultReverseLimit),
		handshakeTimeout: config.DefaultHandshakeTimeout,
		udpIdle:          config.DefaultUDPIdleTimeout,
		maxUDPSessions:   config.DefaultMaxUDPSessions,
	}
	return h
}

func (h *Handler) Init(md metadata.Metadata) error {
	if md == nil {
		return nil
	}
	if v := md.Get("handshake_timeout"); v != nil {
		if d, ok := v.(time.Duration); ok && d > 0 {
			h.handshakeTimeout = d
		}
	}
	if v := md.Get("udp_idle"); v != nil {
		if d, ok := v.(time.Duration); ok && d > 0 {
			h.udpIdle = d
		}
	}
	if v := md.Get("max_udp_sessions"); v != nil {
		if n, ok := v.(int); ok && n > 0 {
			h.maxUDPSessions = n
		}
	}
	return nil
}

func (h *Handler) Handle(ctx context.Context, conn net.Conn, _ ...handler.HandleOption) error {
	select {
	case h.limit <- struct{}{}:
		defer func() { <-h.limit }()
	default:
		if h.options.Logger != nil {
			h.options.Logger.Warn("Reverse server connection limit reached, rejecting %s", conn.RemoteAddr())
		}
		_ = conn.Close()
		return nil
	}

	defer conn.Close()

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	_ = conn.SetReadDeadline(time.Now().Add(h.handshakeTimeout))

	peek, err := br.Peek(1)
	if err != nil {
		return err
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
		return nil
	}

	var authFn func(string, string) bool
	if h.requireAuth {
		authFn = h.auth.Check
	}

	host, port, isUDP, err := rproto.Socks5ServerBind(br, bw, authFn)
	if err != nil {
		return err
	}

	bindAddr := net.JoinHostPort(host, strconv.Itoa(port))

	var ln net.Listener
	var udpLn *net.UDPConn
	var network string

	if isUDP {
		network = "udp"
		uaddr, err := net.ResolveUDPAddr("udp", bindAddr)
		if err != nil {
			return err
		}
		udpLn, err = net.ListenUDP("udp", uaddr)
		if err != nil {
			return err
		}
		defer udpLn.Close()
	} else {
		network = "tcp"
		ln, err = net.Listen("tcp", bindAddr)
		if err != nil {
			return err
		}
		defer ln.Close()
	}

	if err := rproto.WriteBindSuccess(bw, host, port); err != nil {
		return err
	}

	if h.options.Logger != nil {
		h.options.Logger.Info("Reverse server bound %s (%s), bridging to client %s", bindAddr, network, conn.RemoteAddr())
	}

	conf := rev.NewYamuxConfig(h.options.Logger)

	_ = conn.SetReadDeadline(time.Time{})

	session, err := yamux.Client(conn, conf)
	if err != nil {
		return err
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

	if h.options.Logger != nil {
		h.options.Logger.Info("Reverse session established for %s", bindAddr)
	}

	if isUDP {
		return h.handleBoundUDP(ctx, session, udpLn)
	}

	for {
		lc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go h.handleBoundConn(ctx, session, lc)
	}
}

func (h *Handler) handleBoundConn(ctx context.Context, session *yamux.Session, clientConn net.Conn) {
	defer clientConn.Close()

	src := clientConn.RemoteAddr().String()
	bound := clientConn.LocalAddr().String()
	tunnelRemote := session.RemoteAddr().String()

	if h.options.Logger != nil {
		h.options.Logger.Info("Forward Reverse Client Received connection %s --> %s --> %s", src, bound, tunnelRemote)
	}

	stream, err := session.Open()
	if err != nil {
		if h.options.Logger != nil {
			h.options.Logger.Error("Reverse server open stream error: %v", err)
		}
		return
	}
	defer stream.Close()

	bytes, dur, err := inet.Bidirectional(ctx, clientConn, stream)
	if err != nil && ctx.Err() == nil {
		if h.options.Logger != nil {
			h.options.Logger.Error("Reverse server transfer error: %v", err)
		}
	}
	if h.options.Logger != nil {
		h.options.Logger.Debug("Reverse TCP Closed connection %s --> %s transferred %d bytes in %s", src, stream.RemoteAddr().String(), bytes, dur)
	}
}

func (h *Handler) handleBoundUDP(ctx context.Context, session *yamux.Session, conn *net.UDPConn) error {
	type udpSession struct {
		stream   net.Conn
		ps       *inet.PacketStream
		lastSeen time.Time
	}

	activeSessions := make(map[string]*udpSession)
	idleTimeout := h.udpIdle
	if idleTimeout <= 0 {
		idleTimeout = config.DefaultUDPIdleTimeout
	}
	maxSessions := h.maxUDPSessions
	if maxSessions <= 0 {
		maxSessions = config.DefaultMaxUDPSessions
	}

	pkt := pool.Get()
	defer pool.Put(pkt)
	bound := conn.LocalAddr().String()
	tunnelRemote := session.RemoteAddr().String()

	cleanupIdle := func() {
		now := time.Now()
		for k, sess := range activeSessions {
			if now.Sub(sess.lastSeen) > idleTimeout {
				_ = sess.stream.Close()
				delete(activeSessions, k)
				if h.options.Logger != nil {
					h.options.Logger.Debug("Reverse UDP session %s idle timeout", k)
				}
			}
		}
	}

	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFromUDP(pkt)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				cleanupIdle()
				continue
			}
			return err
		}

		srcKey := src.String()
		sess, ok := activeSessions[srcKey]
		if !ok {
			if len(activeSessions) >= maxSessions {
				cleanupIdle()
				if len(activeSessions) >= maxSessions {
					if h.options.Logger != nil {
						h.options.Logger.Warn("Reverse UDP max sessions reached, dropping packet from %s", srcKey)
					}
					continue
				}
			}

			if h.options.Logger != nil {
				h.options.Logger.Info("Forward Reverse Client Received connection %s --> %s --> %s", srcKey, bound, tunnelRemote)
			}

			stream, err := session.Open()
			if err != nil {
				if h.options.Logger != nil {
					h.options.Logger.Error("Reverse UDP Open stream error: %v", err)
				}
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
				buf := pool.Get()
				defer pool.Put(buf)
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
			if h.options.Logger != nil {
				h.options.Logger.Error("Reverse UDP Write to stream error: %v", err)
			}
			_ = sess.stream.Close()
			delete(activeSessions, srcKey)
		}
	}
}
