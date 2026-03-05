package xraymux

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"

	"forward/base/logging"
	"forward/internal/chain"
	"forward/internal/router"
)

// RouteDispatcher adapts the project router to xray routing.Dispatcher.
type RouteDispatcher struct {
	router router.Router
	logger *logging.Logger
}

func NewRouteDispatcher(r router.Router, logger *logging.Logger) *RouteDispatcher {
	return &RouteDispatcher{router: r, logger: logger}
}

func (*RouteDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*RouteDispatcher) Start() error      { return nil }
func (*RouteDispatcher) Close() error      { return nil }

func (d *RouteDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	if d == nil || d.router == nil {
		return nil, fmt.Errorf("mux dispatcher router is nil")
	}
	if !dest.IsValid() {
		return nil, fmt.Errorf("invalid destination")
	}

	uplinkReader, uplinkWriter := pipe.New(pipe.WithSizeLimit(64 * 1024))
	downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(64 * 1024))

	inboundLink := &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}
	outboundLink := &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}

	go func() {
		if err := d.dispatchLink(ctx, dest, outboundLink); err != nil && d.logger != nil {
			d.logger.Debug("mux dispatch %s failed: %v", dest, err)
		}
	}()

	return inboundLink, nil
}

func (d *RouteDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	if d == nil || d.router == nil {
		return fmt.Errorf("mux dispatcher router is nil")
	}
	if link == nil {
		return fmt.Errorf("mux dispatch link is nil")
	}
	if !dest.IsValid() {
		return fmt.Errorf("invalid destination")
	}
	return d.dispatchLink(ctx, dest, link)
}

func (d *RouteDispatcher) dispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	network, address := destinationToDialTarget(dest)

	rt, err := d.router.Route(ctx, network, address)
	if err != nil {
		common.Interrupt(link.Reader)
		common.Close(link.Writer)
		return err
	}
	if rt == nil {
		rt = chain.NewRoute()
	}

	conn, err := rt.Dial(ctx, network, address)
	if err != nil {
		common.Interrupt(link.Reader)
		common.Close(link.Writer)
		return err
	}
	defer conn.Close()

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
			common.Interrupt(link.Reader)
			common.Close(link.Writer)
		case <-stop:
		}
	}()

	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		errCh <- buf.Copy(link.Reader, buf.NewWriter(conn))
	}()

	go func() {
		defer wg.Done()
		errCh <- buf.Copy(buf.NewReader(conn), link.Writer)
	}()

	wg.Wait()
	close(stop)
	close(errCh)

	common.Interrupt(link.Reader)
	common.Close(link.Writer)

	var first error
	for err := range errCh {
		if err == nil || err == io.EOF {
			continue
		}
		if first == nil {
			first = err
		}
	}
	return first
}

func destinationToDialTarget(dest xnet.Destination) (string, string) {
	network := "tcp"
	if dest.Network == xnet.Network_UDP {
		network = "udp"
	}
	return network, net.JoinHostPort(dest.Address.String(), dest.Port.String())
}

var _ routing.Dispatcher = (*RouteDispatcher)(nil)
