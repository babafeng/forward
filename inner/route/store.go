package route

import (
	"context"
	"sync"
	"sync/atomic"

	"forward/inner/endpoint"
	"forward/inner/logging"
)

type Store struct {
	mu      sync.RWMutex
	router  *Router
	cfg     *Config
	version atomic.Uint64
}

func NewStore(cfg *Config, log *logging.Logger) (*Store, error) {
	router, err := NewRouter(cfg, log)
	if err != nil {
		return nil, err
	}
	s := &Store{
		router: router,
		cfg:    cfg,
	}
	return s, nil
}

func (s *Store) Decide(ctx context.Context, address string) (Decision, error) {
	if s == nil {
		return Decision{Via: "DIRECT"}, nil
	}
	s.mu.RLock()
	router := s.router
	s.mu.RUnlock()
	if router == nil {
		return Decision{Via: "DIRECT"}, nil
	}
	return router.Decide(ctx, address)
}

func (s *Store) GetProxy(name string) (endpoint.Endpoint, bool) {
	if s == nil {
		return endpoint.Endpoint{}, false
	}
	key := NormalizeProxyName(name)
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	if cfg == nil || cfg.Proxies == nil {
		return endpoint.Endpoint{}, false
	}
	ep, ok := cfg.Proxies[key]
	return ep, ok
}

func (s *Store) Version() uint64 {
	if s == nil {
		return 0
	}
	return s.version.Load()
}

func (s *Store) Update(cfg *Config, log *logging.Logger) error {
	router, err := NewRouter(cfg, log)
	if err != nil {
		return err
	}
	var old *Router
	s.mu.Lock()
	old = s.router
	s.router = router
	s.cfg = cfg
	s.mu.Unlock()
	s.version.Add(1)
	if old != nil {
		_ = old.Close()
	}
	return nil
}
