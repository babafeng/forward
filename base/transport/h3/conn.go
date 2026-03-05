package h3

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"forward/base/logging"
)

const (
	writeBatchMaxBytes = 256 * 1024
	writeBatchWait     = 2 * time.Millisecond
)

func NewClientConn(client *http.Client, pushURL, pullURL, secret string, remoteAddr net.Addr, logger *logging.Logger) net.Conn {
	if remoteAddr == nil {
		remoteAddr = &net.TCPAddr{}
	}
	c := &clientConn{
		client:     client,
		pushURL:    pushURL,
		pullURL:    pullURL,
		secret:     secret,
		txc:        make(chan []byte, 256),
		rxc:        make(chan []byte, 128),
		closed:     make(chan struct{}),
		localAddr:  &net.TCPAddr{},
		remoteAddr: remoteAddr,
		logger:     logger,
	}
	go c.readLoop()
	go c.writeLoop()
	return c
}

func NewServerConn(conn net.Conn, localAddr, remoteAddr net.Addr) net.Conn {
	if localAddr == nil {
		localAddr = &net.TCPAddr{}
	}
	if remoteAddr == nil {
		remoteAddr = &net.TCPAddr{}
	}
	return &serverConn{
		Conn:       conn,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

type clientConn struct {
	client     *http.Client
	pushURL    string
	pullURL    string
	secret     string
	buf        []byte
	txc        chan []byte
	rxc        chan []byte
	closed     chan struct{}
	mu         sync.Mutex
	localAddr  net.Addr
	remoteAddr net.Addr
	logger     *logging.Logger
}

func (c *clientConn) Read(b []byte) (n int, err error) {
	if len(c.buf) == 0 {
		select {
		case c.buf = <-c.rxc:
		case <-c.closed:
			return 0, io.ErrClosedPipe
		}
	}

	n = copy(b, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *clientConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.isClosed() {
		return 0, io.ErrClosedPipe
	}

	// Copy caller buffer; writes are batched asynchronously into POST bodies.
	pkt := append([]byte(nil), b...)
	select {
	case c.txc <- pkt:
		return len(b), nil
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}

func (c *clientConn) writeLoop() {
	batch := make([][]byte, 0, 32)
	for {
		var first []byte
		select {
		case first = <-c.txc:
		case <-c.closed:
			return
		}
		if len(first) == 0 {
			continue
		}

		total := len(first)
		batch = append(batch, first)

		timer := time.NewTimer(writeBatchWait)
	drain:
		for total < writeBatchMaxBytes {
			select {
			case pkt := <-c.txc:
				if len(pkt) == 0 {
					continue
				}
				total += len(pkt)
				batch = append(batch, pkt)
				if total >= writeBatchMaxBytes {
					break drain
				}
			case <-timer.C:
				break drain
			case <-c.closed:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		if err := c.postBatch(batch); err != nil {
			if c.logger != nil {
				c.logger.Debug("pht: client write loop error: %v", err)
			}
			_ = c.Close()
			return
		}
		batch = batch[:0]
	}
}

func (c *clientConn) postBatch(batch [][]byte) error {
	if len(batch) == 0 {
		return nil
	}
	var payload bytes.Buffer
	for _, pkt := range batch {
		if len(pkt) == 0 {
			continue
		}
		payload.WriteString(base64.StdEncoding.EncodeToString(pkt))
		payload.WriteByte('\n')
	}
	if payload.Len() == 0 {
		return nil
	}

	// Bound request time to avoid blocking the write loop indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.pushURL, &payload)
	if err != nil {
		return err
	}
	if c.secret != "" {
		req.Header.Set("X-PHT-Secret", c.secret)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("push batch failed: %s", resp.Status)
	}

	return nil
}

func (c *clientConn) readLoop() {
	for {
		if c.isClosed() {
			return
		}

		done := true
		err := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.pullURL, nil)
			if err != nil {
				return err
			}
			if c.secret != "" {
				req.Header.Set("X-PHT-Secret", c.secret)
			}

			resp, err := c.client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return errors.New(resp.Status)
			}

			scanner := bufio.NewScanner(resp.Body)
			const maxTokenSize = 1024 * 1024
			scanner.Buffer(make([]byte, maxTokenSize), maxTokenSize)
			for scanner.Scan() {
				done = false
				if scanner.Text() == "" {
					continue
				}
				b, err := base64.StdEncoding.DecodeString(scanner.Text())
				if err != nil {
					return err
				}
				select {
				case c.rxc <- b:
				case <-c.closed:
					return net.ErrClosed
				}
			}
			return scanner.Err()
		}()

		if err != nil {
			c.Close()
			if c.logger != nil {
				c.logger.Debug("pht: client read loop error: %v", err)
			}
			return
		}

		if done {
			return
		}
	}
}

func (c *clientConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *clientConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *clientConn) Close() error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil
	default:
		close(c.closed)
	}
	c.mu.Unlock()
	return nil
}

func (c *clientConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return true
	default:
	}
	return false
}

func (c *clientConn) SetReadDeadline(time.Time) error  { return nil }
func (c *clientConn) SetWriteDeadline(time.Time) error { return nil }
func (c *clientConn) SetDeadline(time.Time) error      { return nil }

type serverConn struct {
	net.Conn
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (c *serverConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *serverConn) RemoteAddr() net.Addr { return c.remoteAddr }
