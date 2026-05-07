package muxshared

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	xmux "github.com/xtls/xray-core/common/mux"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"

	"forward/base/logging"
)

type Worker struct {
	Worker   *xmux.ClientWorker
	LastUsed atomic.Int64
}

func NewWorker(worker *xmux.ClientWorker) *Worker {
	w := &Worker{Worker: worker}
	w.Touch()
	return w
}

func (w *Worker) Touch() {
	w.LastUsed.Store(time.Now().UnixNano())
}

type Manager struct {
	Idle     time.Duration
	Disabled atomic.Bool

	mu      sync.Mutex
	workers []*Worker
}

func (m *Manager) Connect(ctx context.Context, conn net.Conn, network, address string, create func(context.Context, net.Conn) (*Worker, error), bootstrapPrefix, dispatchPrefix string) (net.Conn, bool, error) {
	for _, w := range m.Snapshot() {
		streamConn, err := Dispatch(ctx, w.Worker, network, address)
		if err == nil {
			w.Touch()
			_ = conn.Close()
			return streamConn, false, nil
		}
	}

	w, err := create(ctx, conn)
	if err != nil {
		return nil, true, fmt.Errorf("%s mux bootstrap failed: %w", bootstrapPrefix, err)
	}
	m.Add(w)

	streamConn, err := Dispatch(ctx, w.Worker, network, address)
	if err != nil {
		_ = w.Worker.Close()
		m.Remove(w.Worker)
		return nil, true, fmt.Errorf("%s mux dispatch failed: %w", dispatchPrefix, err)
	}
	w.Touch()
	return streamConn, true, nil
}

func (m *Manager) Disable(reason error, logger *logging.Logger, name string) {
	if !m.Disabled.CompareAndSwap(false, true) {
		return
	}
	if logger != nil {
		logger.Warn("%s mux disabled, fallback to direct forwarding: %v", name, reason)
	}
	m.mu.Lock()
	workers := m.workers
	m.workers = nil
	m.mu.Unlock()
	for _, w := range workers {
		if w != nil && w.Worker != nil {
			_ = w.Worker.Close()
		}
	}
}

func (m *Manager) Snapshot() []*Worker {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.workers) == 0 {
		return nil
	}
	alive := m.workers[:0]
	for _, w := range m.workers {
		if w == nil || w.Worker == nil || w.Worker.Closed() {
			continue
		}
		alive = append(alive, w)
	}
	m.workers = alive
	out := make([]*Worker, len(m.workers))
	copy(out, m.workers)
	return out
}

func (m *Manager) Add(w *Worker) {
	if w == nil || w.Worker == nil {
		return
	}
	m.mu.Lock()
	m.workers = append(m.workers, w)
	m.mu.Unlock()
}

func (m *Manager) Remove(worker *xmux.ClientWorker) {
	if worker == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.workers) == 0 {
		return
	}
	alive := m.workers[:0]
	for _, w := range m.workers {
		if w == nil || w.Worker == nil || w.Worker == worker || w.Worker.Closed() {
			continue
		}
		alive = append(alive, w)
	}
	m.workers = alive
}

func (m *Manager) Watch(w *Worker, conn net.Conn) {
	if m.Idle <= 0 {
		<-w.Worker.WaitClosed()
		_ = conn.Close()
		m.Remove(w.Worker)
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.Worker.WaitClosed():
			_ = conn.Close()
			m.Remove(w.Worker)
			return
		case <-ticker.C:
			last := time.Unix(0, w.LastUsed.Load())
			if w.Worker.ActiveConnections() == 0 && !last.IsZero() && time.Since(last) > m.Idle {
				_ = w.Worker.Close()
			}
		}
	}
}

func Dispatch(ctx context.Context, worker *xmux.ClientWorker, network, address string) (net.Conn, error) {
	target, err := ParseDestination(network, address)
	if err != nil {
		return nil, err
	}

	uplinkReader, uplinkWriter := pipe.New(pipe.WithSizeLimit(64 * 1024))
	downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(64 * 1024))

	link := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}
	dispatchCtx := session.ContextWithOutbounds(ctx, []*session.Outbound{
		{Target: target},
	})

	if !worker.Dispatch(dispatchCtx, link) {
		common.Interrupt(downlinkReader)
		common.Close(downlinkWriter)
		common.Interrupt(uplinkReader)
		common.Close(uplinkWriter)
		return nil, fmt.Errorf("mux worker is full or closed")
	}

	return cnc.NewConnection(
		cnc.ConnectionInputMulti(downlinkWriter),
		cnc.ConnectionOutputMulti(uplinkReader),
		cnc.ConnectionOnClose(&streamCloseHook{
			input:  downlinkWriter,
			output: uplinkReader,
		}),
	), nil
}

func ParseDestination(network, address string) (xnet.Destination, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return xnet.Destination{}, fmt.Errorf("invalid target address %q: %w", address, err)
	}
	port, err := xnet.PortFromString(portStr)
	if err != nil {
		return xnet.Destination{}, fmt.Errorf("invalid target port %q: %w", portStr, err)
	}
	if strings.HasPrefix(strings.ToLower(network), "udp") {
		return xnet.UDPDestination(xnet.ParseAddress(host), port), nil
	}
	return xnet.TCPDestination(xnet.ParseAddress(host), port), nil
}

type streamCloseHook struct {
	input  *pipe.Writer
	output *pipe.Reader
}

func (h *streamCloseHook) Close() error {
	if h.output != nil {
		common.Interrupt(h.output)
	}
	if h.input != nil {
		return h.input.Close()
	}
	return nil
}
