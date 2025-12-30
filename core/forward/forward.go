package forward

import (
	"container/heap"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go-forward/core/proxy"
	"go-forward/core/utils"
)

// Start 启动端口转发服务
// 格式: [protocol://]local//remote
// 例如: :8080//1.2.3.4:80 或 tcp://:8080//1.2.3.4:80
func Start(listenURL string, forwardURL string) {
	var protocol, local, remote string
	if strings.HasPrefix(listenURL, "tcp://") {
		protocol = "tcp"
		listenURL = strings.TrimPrefix(listenURL, "tcp://")

	} else if strings.HasPrefix(listenURL, "udp://") {
		protocol = "udp"
		listenURL = strings.TrimPrefix(listenURL, "udp://")
	} else {
		protocol = "tcp"
	}

	var scheme, _, forwardAddr string
	if forwardURL != "" {
		scheme, _, forwardAddr = utils.URLParse(forwardURL)
	}

	parts := strings.Split(listenURL, "//")
	if len(parts) != 2 {
		utils.Error("Invalid forward URL: %s", listenURL)
		return
	}

	local = parts[0]
	remote = parts[1]

	// 规范化本地地址，如果没有 : 则添加
	if !strings.Contains(local, ":") {
		local = ":" + local
	}

	utils.Info("Forwarding %s %s --> %s via [%s %v]", protocol, local, remote, scheme, forwardAddr)

	if protocol == "udp" {
		startUDP(local, remote, forwardURL)
	} else {
		startTCP(local, remote, forwardURL)
	}
}

func startTCP(local, remote string, forwardURL string) {
	l, err := net.Listen("tcp", local)
	if err != nil {
		utils.Error("TCP Listen error: %v", err)
		return
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			utils.Error("TCP Accept error: %v", err)
			continue
		}
		go handleTCP(conn, remote, forwardURL)
	}
}

func handleTCP(conn net.Conn, remote string, forwardURL string) {
	defer conn.Close()

	rConn, err := proxy.Dial("tcp", remote, forwardURL)
	if err != nil {
		utils.Error("Dial error: %v", err)
		return
	}
	defer rConn.Close()

	utils.Transfer(conn, rConn, remote, "Forward", "TCP")
}

func startUDP(local, remote string, forwardURL string) {
	addr, err := net.ResolveUDPAddr("udp", local)
	if err != nil {
		utils.Error("UDP Resolve error: %v", err)
		return
	}
	var scheme, _, forwardAddr string
	if forwardURL != "" {
		scheme, _, forwardAddr = utils.URLParse(forwardURL)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		utils.Error("UDP Listen error: %v", err)
		return
	}
	defer conn.Close()

	utils.Info("UDP Forwarder listening on %s via [%s %v]", local, scheme, forwardAddr)

	store := newUDPSessionStore(2 * time.Minute)
	cleanupTicker := time.NewTicker(5 * time.Second)
	defer cleanupTicker.Stop()
	go func() {
		for range cleanupTicker.C {
			expired := store.CleanupExpired()
			for _, s := range expired {
				s.conn.Close()
			}
		}
	}()

	buf := utils.GetPacketBuffer()
	defer utils.PutPacketBuffer(buf)
	for {
		n, srcAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			utils.Error("UDP Read error: %v", err)
			continue
		}

		// 获取或创建会话
		key := srcAddr.String()
		val, ok := store.Get(key)
		var session *udpSession

		if !ok {
			utils.Info("Forwarding UDP %s -> %s --> %s via [%s %v]", key, local, remote, scheme, forwardAddr)
			remoteConn, err := proxy.Dial("udp", remote, forwardURL)
			if err != nil {
				utils.Error("UDP Dial error: %v", err)
				continue
			}

			session = &udpSession{conn: remoteConn}
			session.lastActive.Store(time.Now().UnixNano())
			store.Add(key, session)

			go func(s *udpSession, clientAddr *net.UDPAddr, k string) {
				defer s.conn.Close()
				defer store.Delete(k)

				rbuf := utils.GetPacketBuffer()
				defer utils.PutPacketBuffer(rbuf)
				for {
					s.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
					rn, err := s.conn.Read(rbuf)
					if err != nil {
						return
					}
					s.lastActive.Store(time.Now().UnixNano())
					store.Touch(k)
					_, err = conn.WriteToUDP(rbuf[:rn], clientAddr)
					if err != nil {
						return
					}
				}
			}(session, srcAddr, key)
		} else {
			session = val
		}

		session.conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		_, err = session.conn.Write(buf[:n])
		if err != nil {
			store.Delete(key)
			session.conn.Close()
			continue
		}
		session.lastActive.Store(time.Now().UnixNano())
		store.Touch(key)
	}
}

type udpSession struct {
	conn       net.Conn
	lastActive atomic.Int64
}

type udpSessionEntry struct {
	key       string
	session   *udpSession
	expiresAt time.Time
	index     int
}

type udpSessionHeap []*udpSessionEntry

func (h udpSessionHeap) Len() int { return len(h) }

func (h udpSessionHeap) Less(i, j int) bool {
	return h[i].expiresAt.Before(h[j].expiresAt)
}

func (h udpSessionHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *udpSessionHeap) Push(x any) {
	entry := x.(*udpSessionEntry)
	entry.index = len(*h)
	*h = append(*h, entry)
}

func (h *udpSessionHeap) Pop() any {
	old := *h
	n := len(old)
	entry := old[n-1]
	entry.index = -1
	*h = old[:n-1]
	return entry
}

type udpSessionStore struct {
	mu       sync.Mutex
	sessions map[string]*udpSessionEntry
	expiry   udpSessionHeap
	ttl      time.Duration
}

func newUDPSessionStore(ttl time.Duration) *udpSessionStore {
	return &udpSessionStore{
		sessions: make(map[string]*udpSessionEntry),
		ttl:      ttl,
	}
}

func (s *udpSessionStore) Get(key string) (*udpSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[key]
	if !ok {
		return nil, false
	}
	return entry.session, true
}

func (s *udpSessionStore) Add(key string, session *udpSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := &udpSessionEntry{
		key:       key,
		session:   session,
		expiresAt: time.Now().Add(s.ttl),
	}
	heap.Push(&s.expiry, entry)
	s.sessions[key] = entry
}

func (s *udpSessionStore) Touch(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[key]
	if !ok {
		return
	}
	entry.expiresAt = time.Now().Add(s.ttl)
	heap.Fix(&s.expiry, entry.index)
}

func (s *udpSessionStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[key]
	if !ok {
		return
	}
	heap.Remove(&s.expiry, entry.index)
	delete(s.sessions, key)
}

func (s *udpSessionStore) CleanupExpired() []*udpSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var expired []*udpSession
	for len(s.expiry) > 0 {
		entry := s.expiry[0]
		if entry.expiresAt.After(now) {
			break
		}
		heap.Pop(&s.expiry)
		delete(s.sessions, entry.key)
		expired = append(expired, entry.session)
	}
	return expired
}
