package route

import (
	"context"
	"strings"

	"forward/internal/logging"
)

func RouteVia(ctx context.Context, store *Store, log *logging.Logger, src, dst string) (string, error) {
	if store == nil {
		return "DIRECT", nil
	}
	decision, err := store.Decide(ctx, dst)
	if err != nil {
		return "DIRECT", err
	}
	if log != nil {
		log.Info("Forward Route %s --> %s via %s", src, dst, decision.Via)
	}
	return decision.Via, nil
}

func IsReject(via string) bool {
	return strings.EqualFold(via, "REJECT")
}
