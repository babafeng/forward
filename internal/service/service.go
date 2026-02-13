package service

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"forward/base/logging"
	"forward/internal/config"
	ictx "forward/internal/ctx"
	"forward/internal/handler"
	"forward/internal/listener"
	"forward/internal/metadata"
)

var connSeq atomic.Uint64

type Service interface {
	Serve() error
	Addr() net.Addr
	Close() error
}

type defaultService struct {
	listener listener.Listener
	handler  handler.Handler
	logger   *logging.Logger
	verbose  bool
	conns    sync.Map
}

func NewService(ln listener.Listener, h handler.Handler, logger *logging.Logger, verbose bool) Service {
	return &defaultService{
		listener: ln,
		handler:  h,
		logger:   logger,
		verbose:  verbose,
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

		src := conn.RemoteAddr().String()
		local := conn.LocalAddr().String()
		id := connSeq.Add(1)
		trace := &ictx.Trace{ID: id, Src: src, Local: local, Logger: s.logger, Verbose: s.verbose}

		if s.logger != nil && s.verbose {
			s.logger.Debug("%saccept %s -> %s", trace.Prefix(), src, local)
		}

		baseCtx := context.Background()
		if cc, ok := conn.(interface{ Context() context.Context }); ok {
			if cctx := cc.Context(); cctx != nil {
				baseCtx = cctx
			}
		}
		ctx, cancel := context.WithCancel(baseCtx)
		ctx = ictx.ContextWithTrace(ctx, trace)

		select {
		case sem <- struct{}{}:
		default:
			if s.logger != nil {
				s.logger.Warn("%sreject %s -> %s: max connection limit reached", trace.Prefix(), src, local)
			}
			conn.Close()
			cancel()
			continue
		}

		s.conns.Store(conn, cancel)
		wg.Add(1)
		go func(c net.Conn, cctx context.Context, cancel context.CancelFunc, tr *ictx.Trace) {
			defer func() { <-sem }()
			defer wg.Done()
			defer s.conns.Delete(c)
			defer cancel()

			if s.logger != nil && s.verbose {
				s.logger.Debug("%shandle %s -> %s", tr.Prefix(), tr.Src, tr.Local)
			}
			var hopts []handler.HandleOption
			if mc, ok := c.(interface{ Metadata() metadata.Metadata }); ok {
				if md := mc.Metadata(); md != nil {
					hopts = append(hopts, handler.MetadataHandleOption(md))
				}
			}
			if err := s.handler.Handle(cctx, c, hopts...); err != nil && s.logger != nil && cctx.Err() == nil {
				s.logger.Debug("%shandler error %s -> %s: %v", tr.Prefix(), tr.Src, tr.Local, err)
			}
			// ensure connection is closed
			c.Close()
			if s.logger != nil && s.verbose {
				s.logger.Debug("%sclose %s -> %s", tr.Prefix(), tr.Src, tr.Local)
			}
		}(conn, ctx, cancel, trace)
	}
}
