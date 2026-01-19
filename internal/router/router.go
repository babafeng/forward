package router

import (
	"context"

	"forward/internal/chain"
)

type Router interface {
	Route(ctx context.Context, network, address string) (chain.Route, error)
}
