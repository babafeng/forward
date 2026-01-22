package service

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"forward/base/logging"
	"forward/internal/config"
	"forward/internal/handler"
	"forward/internal/listener"
)

type Service interface {
	Serve() error
	Addr() net.Addr
	Close() error
}

type defaultService struct {
	listener listener.Listener
	handler  handler.Handler
	logger   *logging.Logger
	conns    sync.Map
}

func NewService(ln listener.Listener, h handler.Handler, logger *logging.Logger) Service {
	return &defaultService{
		listener: ln,
		handler:  h,
		logger:   logger,
	}
}

func (s *defaultService) Addr() net.Addr {
	return s.listener.Addr()
}

func (s *defaultService) Close() error {
	err := s.listener.Close()
	s.conns.Range(func(key, value any) bool {
		if cancel, ok := value.(context.CancelFunc); ok {
			cancel()
		}
		if conn, ok := key.(net.Conn); ok {
			conn.Close()
		}
		return true
	})
	return err
}

func (s *defaultService) Serve() error {
	var tempDelay time.Duration
	var wg sync.WaitGroup
	defer wg.Wait()

	// Use global limit for now as per P0-3 plan
	limit := config.DefaultMaxConnections
	sem := make(chan struct{}, limit)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 1 * time.Second
				} else {
					tempDelay *= 2
				}
				if max := 5 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0

		if s.logger != nil {
			s.logger.Debug("Service accepted %s -> %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
		}

		ctx, cancel := context.WithCancel(context.Background())
		if cc, ok := conn.(interface{ Context() context.Context }); ok {
			if cctx := cc.Context(); cctx != nil {
				ctx, cancel = context.WithCancel(cctx)
			}
		}

		select {
		case sem <- struct{}{}:
		default:
			if s.logger != nil {
				s.logger.Warn("Service max connection limit reached, rejected %s", conn.RemoteAddr())
			}
			conn.Close()
			cancel()
			continue
		}

		s.conns.Store(conn, cancel)
		wg.Add(1)
		go func(c net.Conn) {
			defer func() { <-sem }()
			defer wg.Done()
			defer s.conns.Delete(c)
			defer cancel()

			if s.logger != nil {
				s.logger.Debug("Service handling %s -> %s", c.RemoteAddr().String(), c.LocalAddr().String())
			}
			if err := s.handler.Handle(ctx, c); err != nil && s.logger != nil {
				s.logger.Debug("Service handler error %s -> %s: %v", c.RemoteAddr().String(), c.LocalAddr().String(), err)
			}
			// ensure connection is closed
			c.Close()
			if s.logger != nil {
				s.logger.Debug("Service closed %s -> %s", c.RemoteAddr().String(), c.LocalAddr().String())
			}
		}(conn)
	}
}
