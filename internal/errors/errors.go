package errors

import "errors"

var (
	ErrAuthFailed   = errors.New("authentication failed")
	ErrAuthRequired = errors.New("authentication required")
	ErrAccessDenied = errors.New("access denied")
)

var (
	ErrTooManyConnections = errors.New("too many connections")
	ErrTooManyUDPSessions = errors.New("too many UDP sessions")
)

var (
	ErrHeaderTooLarge  = errors.New("header too large")
	ErrInvalidRequest  = errors.New("invalid request")
	ErrInvalidProtocol = errors.New("invalid protocol")
)

var (
	ErrDialTimeout      = errors.New("dial timeout")
	ErrHandshakeTimeout = errors.New("handshake timeout")
	ErrReadTimeout      = errors.New("read timeout")
	ErrWriteTimeout     = errors.New("write timeout")
)

var (
	ErrConnectionClosed = errors.New("connection closed")
	ErrConnectionReset  = errors.New("connection reset")
)
