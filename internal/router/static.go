package router

import (
	"context"

	"forward/internal/chain"
)

type Static struct {
	route chain.Route
}

func NewStatic(route chain.Route) *Static {
	return &Static{route: route}
}

func (s *Static) Route(_ context.Context, _ string, _ string) (chain.Route, error) {
	if s == nil || s.route == nil {
		return chain.NewRoute(), nil
	}
	return s.route, nil
}
