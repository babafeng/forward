package registry

import (
	"errors"
	"io"
	"sync"

	"forward/internal/connector"
	"forward/internal/dialer"
	"forward/internal/handler"
	"forward/internal/listener"
)

var (
	ErrDup = errors.New("registry: duplicate object")
)

type Registry[T any] interface {
	Register(name string, v T) error
	Unregister(name string)
	IsRegistered(name string) bool
	Get(name string) T
	GetAll() map[string]T
}

type registry[T any] struct {
	m sync.Map
}

func (r *registry[T]) Register(name string, v T) error {
	if name == "" {
		return nil
	}
	if _, loaded := r.m.LoadOrStore(name, v); loaded {
		return ErrDup
	}
	return nil
}

func (r *registry[T]) Unregister(name string) {
	if v, ok := r.m.Load(name); ok {
		if closer, ok := v.(io.Closer); ok {
			_ = closer.Close()
		}
		r.m.Delete(name)
	}
}

func (r *registry[T]) IsRegistered(name string) bool {
	_, ok := r.m.Load(name)
	return ok
}

func (r *registry[T]) Get(name string) (t T) {
	if name == "" {
		return
	}
	v, _ := r.m.Load(name)
	t, _ = v.(T)
	return
}

func (r *registry[T]) GetAll() (m map[string]T) {
	m = make(map[string]T)
	r.m.Range(func(key, value any) bool {
		k, _ := key.(string)
		v, _ := value.(T)
		m[k] = v
		return true
	})
	return
}

type NewListener func(opts ...listener.Option) listener.Listener
type NewHandler func(opts ...handler.Option) handler.Handler
type NewDialer func(opts ...dialer.Option) dialer.Dialer
type NewConnector func(opts ...connector.Option) connector.Connector

type listenerRegistry struct{ registry[NewListener] }
type handlerRegistry struct{ registry[NewHandler] }
type dialerRegistry struct{ registry[NewDialer] }
type connectorRegistry struct{ registry[NewConnector] }

var (
	listenerReg  Registry[NewListener]  = new(listenerRegistry)
	handlerReg   Registry[NewHandler]   = new(handlerRegistry)
	dialerReg    Registry[NewDialer]    = new(dialerRegistry)
	connectorReg Registry[NewConnector] = new(connectorRegistry)
)

func ListenerRegistry() Registry[NewListener] {
	return listenerReg
}

func HandlerRegistry() Registry[NewHandler] {
	return handlerReg
}

func DialerRegistry() Registry[NewDialer] {
	return dialerReg
}

func ConnectorRegistry() Registry[NewConnector] {
	return connectorReg
}
