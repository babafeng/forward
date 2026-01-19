package service

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"forward/base/logging"
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
	return s.listener.Close()
}

func (s *defaultService) Serve() error {
	var tempDelay time.Duration
	var wg sync.WaitGroup
	defer wg.Wait()

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

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			if s.logger != nil {
				s.logger.Debug("Service handling %s -> %s", c.RemoteAddr().String(), c.LocalAddr().String())
			}
			if err := s.handler.Handle(context.Background(), c); err != nil && s.logger != nil {
				s.logger.Debug("Service handler error %s -> %s: %v", c.RemoteAddr().String(), c.LocalAddr().String(), err)
			}
			if s.logger != nil {
				s.logger.Debug("Service closed %s -> %s", c.RemoteAddr().String(), c.LocalAddr().String())
			}
		}(conn)
	}
}
