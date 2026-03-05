package route

import (
	"context"
	"sync"
	"sync/atomic"

	"forward/base/endpoint"
	"forward/base/logging"
)

type Store struct {
	mu      sync.Mutex
	router  atomic.Pointer[Router]
	cfg     atomic.Pointer[Config]
	version atomic.Uint64
}

func NewStore(cfg *Config, log *logging.Logger) (*Store, error) {
	router, err := NewRouter(cfg, log)
	if err != nil {
		return nil, err
	}
	s := &Store{}
	s.router.Store(router)
	s.cfg.Store(cfg)
	return s, nil
}

func (s *Store) Decide(ctx context.Context, address string) (Decision, error) {
	if s == nil {
		return Decision{Via: "DIRECT"}, nil
	}
	router := s.router.Load()
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
	cfg := s.cfg.Load()
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
	s.mu.Lock()
	old := s.router.Swap(router)
	s.cfg.Store(cfg)
	s.mu.Unlock()
	s.version.Add(1)
	if old != nil {
		_ = old.Close()
	}
	return nil
}
