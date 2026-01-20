package h3

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"forward/base/logging"
)

func NewClientConn(client *http.Client, pushURL, pullURL string, remoteAddr net.Addr, logger *logging.Logger) net.Conn {
	if remoteAddr == nil {
		remoteAddr = &net.TCPAddr{}
	}
	c := &clientConn{
		client:     client,
		pushURL:    pushURL,
		pullURL:    pullURL,
		rxc:        make(chan []byte, 128),
		closed:     make(chan struct{}),
		localAddr:  &net.TCPAddr{},
		remoteAddr: remoteAddr,
		logger:     logger,
	}
	go c.readLoop()
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
	buf        []byte
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
	return c.write(b)
}

func (c *clientConn) write(b []byte) (n int, err error) {
	if c.isClosed() {
		return 0, io.ErrClosedPipe
	}

	var r io.Reader
	if len(b) > 0 {
		buf := bytes.NewBufferString(base64.StdEncoding.EncodeToString(b))
		buf.WriteByte('\n')
		r = buf
	}

	req, err := http.NewRequest(http.MethodPost, c.pushURL, r)
	if err != nil {
		return 0, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, errors.New(resp.Status)
	}

	return len(b), nil
}

func (c *clientConn) readLoop() {
	for {
		if c.isClosed() {
			return
		}

		done := true
		err := func() error {
			req, err := http.NewRequest(http.MethodGet, c.pullURL, nil)
			if err != nil {
				return err
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

	_, err := c.write(nil)
	return err
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
