package xraymux

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

// Bidirectional双向复制 Xray buf.Reader/Writer
func Bidirectional(ctx context.Context, clientConn net.Conn, targetConn net.Conn, clientReader buf.Reader, clientWriter buf.Writer, targetReader buf.Reader, targetWriter buf.Writer) error {
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if clientConn != nil {
				_ = clientConn.Close()
			}
			if targetConn != nil {
				_ = targetConn.Close()
			}
			if clientReader != nil {
				common.Interrupt(clientReader)
			}
			if clientWriter != nil {
				common.Close(clientWriter)
			}
			if targetReader != nil {
				common.Interrupt(targetReader)
			}
			if targetWriter != nil {
				common.Close(targetWriter)
			}
		case <-stop:
		}
	}()

	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		errCh <- buf.Copy(clientReader, targetWriter)
	}()

	go func() {
		defer wg.Done()
		errCh <- buf.Copy(targetReader, clientWriter)
	}()

	wg.Wait()
	close(stop)

	if clientConn != nil {
		_ = clientConn.Close()
	}
	if targetConn != nil {
		_ = targetConn.Close()
	}
	if clientReader != nil {
		common.Interrupt(clientReader)
	}
	if clientWriter != nil {
		common.Close(clientWriter)
	}
	if targetReader != nil {
		common.Interrupt(targetReader)
	}
	if targetWriter != nil {
		common.Close(targetWriter)
	}

	var first error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && err != io.EOF && first == nil {
			first = err
		}
	}
	return first
}
