package http

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"forward/base/logging"
	"forward/base/pool"
	"forward/internal/chain"
	"forward/internal/config"
	"forward/internal/handler/udptun"
	"forward/internal/router"
)

func isUDPRequest(req *stdhttp.Request) bool {
	if req == nil {
		return false
	}
	return strings.EqualFold(req.Header.Get("X-Forward-Protocol"), "udp")
}

func (h *Handler) handleUDP(ctx context.Context, conn net.Conn, br *bufio.Reader) error {
	if !h.enableUDP {
		return writeSimple(conn, stdhttp.StatusForbidden, config.CamouflagePageTitle, nil)
	}

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}

	if br != nil && br.Buffered() > 0 {
		conn = &readWriteConn{Conn: conn, r: br}
	}

	pc := udptun.ServerConn(conn)
	sess := newUDPSession(h.options.Router, h.log(), pc, h.udpIdle, h.maxUDPSessions)
	sess.run(ctx)
	return nil
}

type udpSession struct {
	router  router.Router
	logger  *logging.Logger
	client  net.PacketConn
	idle    time.Duration
	maxSess int

	mu       sync.Mutex
	sessions map[string]*udpPeer
	sf       singleflight.Group
}

type udpPeer struct {
	conn     net.Conn
	dest     string
	raddr    net.Addr
	lastSeen atomic.Int64
}

func newUDPSession(r router.Router, log *logging.Logger, client net.PacketConn, idle time.Duration, maxSessions int) *udpSession {
	return &udpSession{
		router:   r,
		logger:   log,
		client:   client,
		idle:     idle,
		maxSess:  maxSessions,
		sessions: make(map[string]*udpPeer),
	}
}

func (s *udpSession) run(ctx context.Context) {
	buf := pool.Get()
	defer pool.Put(buf)

	ticker := time.NewTicker(s.idle / 2)
	defer ticker.Stop()

	for {
		_ = s.client.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := s.client.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					s.cleanupIdle()
					continue
				default:
					continue
				}
			}
			return
		}
		if addr == nil {
			continue
		}
		dest := addr.String()

		p := s.getOrCreatePeer(ctx, dest)
		if p == nil {
			continue
		}

		p.lastSeen.Store(time.Now().UnixNano())
		_ = p.conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		_, err = p.conn.Write(buf[:n])
		_ = p.conn.SetWriteDeadline(time.Time{})
		if err != nil {
			s.logf(logging.LevelError, "HTTP UDP write %s error: %v", dest, err)
			s.removePeer(dest)
			p.conn.Close()
		}
	}
}

func (s *udpSession) getOrCreatePeer(ctx context.Context, dest string) *udpPeer {
	s.mu.Lock()
	if p := s.sessions[dest]; p != nil {
		s.mu.Unlock()
		return p
	}
	if len(s.sessions) >= s.maxSess {
		s.mu.Unlock()
		s.logf(logging.LevelWarn, "HTTP UDP session limit reached")
		return nil
	}
	s.mu.Unlock()

	result, _, _ := s.sf.Do(dest, func() (interface{}, error) {
		s.mu.Lock()
		if p := s.sessions[dest]; p != nil {
			s.mu.Unlock()
			return p, nil
		}
		if len(s.sessions) >= s.maxSess {
			s.mu.Unlock()
			return nil, nil
		}
		s.mu.Unlock()

		route, err := s.router.Route(ctx, "udp", dest)
		if err != nil {
			s.logf(logging.LevelError, "HTTP UDP route error: %v", err)
			return nil, err
		}
		if route == nil {
			route = chain.NewRoute()
		}

		c, err := route.Dial(ctx, "udp", dest)
		if err != nil {
			s.logf(logging.LevelError, "HTTP UDP dial %s error: %v", dest, err)
			return nil, err
		}

		raddr, err := net.ResolveUDPAddr("udp", dest)
		if err != nil {
			raddr = &net.UDPAddr{IP: net.IPv4zero}
		}

		p := &udpPeer{
			conn:  c,
			dest:  dest,
			raddr: raddr,
		}
		p.lastSeen.Store(time.Now().UnixNano())

		go s.readUpstream(ctx, p)

		s.mu.Lock()
		s.sessions[dest] = p
		s.mu.Unlock()
		return p, nil
	})

	if result == nil {
		return nil
	}
	return result.(*udpPeer)
}

func (s *udpSession) readUpstream(ctx context.Context, p *udpPeer) {
	defer func() {
		s.removePeer(p.dest)
		p.conn.Close()
	}()

	buf := pool.Get()
	defer pool.Put(buf)

	for {
		_ = p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := p.conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Since(time.Unix(0, p.lastSeen.Load())) > s.idle {
					return
				}
				continue
			}
			return
		}

		_, err = s.client.WriteTo(buf[:n], p.raddr)
		if err != nil {
			return
		}
		p.lastSeen.Store(time.Now().UnixNano())
	}
}

func (s *udpSession) removePeer(key string) {
	s.mu.Lock()
	delete(s.sessions, key)
	s.mu.Unlock()
}

func (s *udpSession) cleanupIdle() {
	now := time.Now()
	s.mu.Lock()
	for k, p := range s.sessions {
		last := time.Unix(0, p.lastSeen.Load())
		if now.Sub(last) > s.idle {
			_ = p.conn.Close()
			delete(s.sessions, k)
		}
	}
	s.mu.Unlock()
}

func (s *udpSession) logf(level logging.Level, format string, args ...any) {
	if s.logger == nil {
		return
	}
	switch level {
	case logging.LevelDebug:
		s.logger.Debug(format, args...)
	case logging.LevelInfo:
		s.logger.Info(format, args...)
	case logging.LevelWarn:
		s.logger.Warn(format, args...)
	case logging.LevelError:
		s.logger.Error(format, args...)
	}
}

type readWriteConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *readWriteConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
