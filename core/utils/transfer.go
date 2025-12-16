package utils

import (
	"io"
	"net"
	"sync"
	"time"
)

func Transfer(src net.Conn, dst net.Conn, targetAddr string, module string, protocol string) {
	start := time.Now()

	var uploaded, downloaded int64
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		uploaded, _ = io.Copy(dst, src)
		dst.Close()
	}()

	go func() {
		defer wg.Done()
		downloaded, _ = io.Copy(src, dst)
		src.Close()
	}()

	wg.Wait()

	duration := time.Since(start)
	total := uploaded + downloaded

	Info("[%s] [%s] %s --> %s --> %s --> %s %d bytes %v", module, protocol, src.RemoteAddr(), src.LocalAddr(), dst.RemoteAddr(), targetAddr, total, duration)
}
