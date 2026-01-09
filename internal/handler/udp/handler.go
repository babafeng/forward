package udp

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"forward/internal/config"
	"forward/internal/dialer"
	"forward/internal/logging"
	"forward/internal/pool"
	"forward/internal/utils"
)

type Handler struct {
	target      string
	dialer      dialer.Dialer
	log         *logging.Logger
	idleTimeout time.Duration

	mu       sync.Mutex
	sessions map[string]*session
	sf       singleflight.Group
}

func New(cfg config.Config, d dialer.Dialer) *Handler {
	idle := cfg.UDPIdleTimeout
	if idle <= 0 {
		idle = 2 * time.Minute
	}
	return &Handler{
		target:      cfg.Forward.Address(),
		dialer:      d,
		log:         cfg.Logger,
		idleTimeout: idle,
		sessions:    make(map[string]*session),
	}
}

func (h *Handler) Handle(ctx context.Context, conn *net.UDPConn, pkt []byte, src *net.UDPAddr) {
	s := h.getOrCreateSession(ctx, conn, src)
	if s == nil {
		pool.Put(pkt)
		return
	}

	s.touch()
	s.bytesIn.Add(int64(len(pkt)))

	_ = s.upstream.SetWriteDeadline(time.Now().Add(1 * time.Second))
	if _, err := s.upstream.Write(pkt); err != nil {
		h.log.Error("[%s] Forward UDP error: write upstream: %v", s.cid, err)
		s.close()
	}
	_ = s.upstream.SetWriteDeadline(time.Time{})
	pool.Put(pkt)
}

func (h *Handler) Close() error {
	h.closeAll()
	return nil
}

func (h *Handler) getOrCreateSession(ctx context.Context, lconn *net.UDPConn, src *net.UDPAddr) *session {
	key := src.String()

	// 快速路径：检查已存在的 session
	h.mu.Lock()
	if s := h.sessions[key]; s != nil {
		h.mu.Unlock()
		return s
	}
	h.mu.Unlock()

	// 使用 singleflight 确保同一 key 只创建一个 session
	result, _, _ := h.sf.Do(key, func() (interface{}, error) {
		// 再次检查，可能其他 goroutine 已创建
		h.mu.Lock()
		if s := h.sessions[key]; s != nil {
			h.mu.Unlock()
			return s, nil
		}
		h.mu.Unlock()

		cid := utils.NewID()
		h.log.Info("[%s] Forward UDP Received connection %s --> %s", cid, key, h.target)
		up, err := h.dialer.DialContext(ctx, "udp", h.target)
		if err != nil {
			h.log.Error("[%s] Forward UDP error: dial %s: %v", cid, h.target, err)
			return nil, err
		}
		h.log.Debug("[%s] Forward UDP Connected to upstream %s --> %s", cid, key, h.target)

		s := &session{
			cid:      cid,
			h:        h,
			key:      key,
			src:      cloneUDPAddr(src),
			upstream: up,
			start:    time.Now(),
			idle:     h.idleTimeout,
			lconn:    lconn,
		}
		s.touch()

		h.mu.Lock()
		h.sessions[key] = s
		h.mu.Unlock()

		go s.run()

		return s, nil
	})

	if result == nil {
		return nil
	}
	return result.(*session)
}

func (h *Handler) deleteSession(key string) {
	h.mu.Lock()
	delete(h.sessions, key)
	h.mu.Unlock()
}

func (h *Handler) closeAll() {
	h.mu.Lock()
	ss := make([]*session, 0, len(h.sessions))
	for _, s := range h.sessions {
		ss = append(ss, s)
	}
	h.mu.Unlock()

	for _, s := range ss {
		s.close()
	}
}

type session struct {
	cid string
	h   *Handler
	key string

	src *net.UDPAddr

	upstream net.Conn
	lconn    *net.UDPConn

	start time.Time
	idle  time.Duration

	lastSeen atomic.Int64

	bytesIn  atomic.Int64
	bytesOut atomic.Int64

	closeOnce sync.Once
}

func (s *session) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
}

func (s *session) run() {
	buf := pool.Get()
	defer pool.Put(buf)

	for {
		_ = s.upstream.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := s.upstream.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if s.isIdle() {
					break
				}
				continue
			}
			break
		}
		if n == 0 {
			continue
		}

		s.h.log.Debug("[%s] Forward UDP Received %d bytes from upstream for %s", s.cid, n, s.src.String())

		s.touch()
		s.bytesOut.Add(int64(n))

		if _, err := s.lconn.WriteToUDP(buf[:n], s.src); err != nil {
			break
		}
	}

	s.close()
}

func (s *session) isIdle() bool {
	last := time.Unix(0, s.lastSeen.Load())
	return time.Since(last) > s.idle
}

func (s *session) close() {
	s.closeOnce.Do(func() {
		_ = s.upstream.Close()
		s.h.deleteSession(s.key)

		total := s.bytesIn.Load() + s.bytesOut.Load()
		dur := time.Since(s.start)
		s.h.log.Debug("[%s] Forward UDP Closed connection %s --> %s transferred %d bytes in %s", s.cid, s.src.String(), s.h.target, total, dur)
	})
}

func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	ip := make(net.IP, len(a.IP))
	copy(ip, a.IP)
	return &net.UDPAddr{
		IP:   ip,
		Port: a.Port,
		Zone: a.Zone,
	}
}
