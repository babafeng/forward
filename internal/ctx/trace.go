package ctx

import (
	"context"
	"fmt"

	"forward/base/logging"
)

// Trace carries per-connection tracing information used for logging.
// It is attached to the connection context by the service layer.
//
// NOTE: This struct is intentionally kept small and logging-focused.
type Trace struct {
	// ID is a monotonically increasing connection identifier.
	ID uint64
	// Src is the client/source address (usually conn.RemoteAddr().String()).
	Src string
	// Local is the local/listen address (usually conn.LocalAddr().String()).
	Local string

	// Logger is the logger used to emit trace logs.
	Logger *logging.Logger
}

type traceKey struct{}

// ContextWithTrace attaches a Trace to ctx.
func ContextWithTrace(ctx context.Context, t *Trace) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, traceKey{}, t)
}

// TraceFromContext extracts Trace from ctx.
func TraceFromContext(ctx context.Context) *Trace {
	if ctx == nil {
		return nil
	}
	t, _ := ctx.Value(traceKey{}).(*Trace)
	return t
}

// Prefix returns a consistent prefix for logs related to this trace.
// Example: "conn#42 ". Returns empty string if trace is absent.
func (t *Trace) Prefix() string {
	if t == nil || t.ID == 0 {
		return ""
	}
	return fmt.Sprintf("conn#%d ", t.ID)
}
