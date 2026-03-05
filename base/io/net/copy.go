package net

import (
	"context"
	"errors"
	"forward/internal/config"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var noHalfCloseFallbackTimeout = 3 * time.Second

var copyBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, config.DefaultCopyBuffer)
	},
}

func Bidirectional(ctx context.Context, in, out net.Conn) (bytes int64, dur time.Duration, err error) {
	start := time.Now()

	var stop chan struct{}
	if done := ctx.Done(); done != nil {
		stop = make(chan struct{})
		go func() {
			select {
			case <-done:
				_ = in.Close()
				_ = out.Close()
			case <-stop:
			}
		}()
	}

	var total atomic.Int64
	resCh := make(chan copyResult, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		buf := getCopyBuffer()
		defer putCopyBuffer(buf)
		n, e := io.CopyBuffer(dst, src, buf)
		if n > 0 {
			total.Add(n)
		}
		halfClosed := closeWrite(dst)
		if errors.Is(e, io.EOF) {
			e = nil
		}
		resCh <- copyResult{
			err:        e,
			halfClosed: halfClosed,
		}
	}

	go pipe(in, out)
	go pipe(out, in)

	first := <-resCh
	second := copyResult{}
	if first.halfClosed {
		second = <-resCh
	} else {
		second = waitSecondResult(ctx, in, out, resCh)
	}
	wg.Wait()
	if stop != nil {
		close(stop)
	}

	_ = in.Close()
	_ = out.Close()

	firstErr := normalizeCopyError(first.err)
	secondErr := normalizeCopyError(second.err)
	if firstErr != nil {
		return total.Load(), time.Since(start), firstErr
	}
	return total.Load(), time.Since(start), secondErr
}

type copyResult struct {
	err        error
	halfClosed bool
}

func closeWrite(c net.Conn) bool {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return true
	}
	return false
}

func waitSecondResult(ctx context.Context, in, out net.Conn, resCh <-chan copyResult) copyResult {
	timer := time.NewTimer(noHalfCloseFallbackTimeout)
	defer timer.Stop()

	ctxDone := ctx.Done()
	select {
	case res := <-resCh:
		return res
	case <-timer.C:
		_ = in.Close()
		_ = out.Close()
		return <-resCh
	case <-ctxDone:
		_ = in.Close()
		_ = out.Close()
		return <-resCh
	}
}

func normalizeCopyError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) || strings.Contains(err.Error(), "use of closed network connection") {
		return nil
	}
	return err
}

func getCopyBuffer() []byte {
	b := copyBufferPool.Get().([]byte)
	if cap(b) < config.DefaultCopyBuffer {
		return make([]byte, config.DefaultCopyBuffer)
	}
	return b[:config.DefaultCopyBuffer]
}

func putCopyBuffer(b []byte) {
	if cap(b) < config.DefaultCopyBuffer {
		return
	}
	copyBufferPool.Put(b[:config.DefaultCopyBuffer])
}
