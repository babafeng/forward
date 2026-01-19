package net

import (
	"context"
	"errors"
	"forward/inner/config"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func Bidirectional(ctx context.Context, in, out net.Conn) (bytes int64, dur time.Duration, err error) {
	start := time.Now()

	// Make sure we stop promptly if the parent context is cancelled.
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = in.Close()
			_ = out.Close()
		case <-stop:
		}
	}()

	var total atomic.Int64
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, config.DefaultCopyBuffer)
		n, e := io.CopyBuffer(dst, src, buf)
		if n > 0 {
			total.Add(n)
		}
		closeWrite(dst)
		if errors.Is(e, io.EOF) {
			e = nil
		}
		errCh <- e
	}

	go pipe(in, out)
	go pipe(out, in)

	wg.Wait()
	close(stop)

	_ = in.Close()
	_ = out.Close()

	var first error
	for i := 0; i < 2; i++ {
		if e := <-errCh; e != nil && first == nil {
			first = e
		}
	}

	if first != nil && (errors.Is(first, net.ErrClosed) || errors.Is(first, io.ErrClosedPipe) || strings.Contains(first.Error(), "use of closed network connection")) {
		first = nil
	}
	return total.Load(), time.Since(start), first
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
}
