package utils

import (
	"io"
	"net"
	"sync"
	"time"
)

func Transfer(src net.Conn, dst net.Conn, targetAddr string, module string, protocol string) {
	start := time.Now()
	defer src.Close()
	defer dst.Close()

	var uploaded, downloaded int64
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		uploaded, _ = copyWithBuffer(dst, src)
		closeWrite(dst)
	}()

	go func() {
		defer wg.Done()
		downloaded, _ = copyWithBuffer(src, dst)
		closeWrite(src)
	}()

	wg.Wait()

	duration := time.Since(start)
	total := uploaded + downloaded

	Info("[%s] [%s] %s --> %s --> %s --> %s %d bytes %v", module, protocol, src.RemoteAddr(), src.LocalAddr(), dst.RemoteAddr(), targetAddr, total, duration)
}

func copyWithBuffer(dst io.Writer, src io.Reader) (int64, error) {
	buf := GetStreamBuffer()
	defer PutStreamBuffer(buf)
	return io.CopyBuffer(dst, src, buf)
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		cw.CloseWrite()
		return
	}
	conn.Close()
}
