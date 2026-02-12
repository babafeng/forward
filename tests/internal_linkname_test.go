package tests

import (
	"net/url"
	"time"

	_ "forward/base/app"
	"forward/base/endpoint"
	_ "forward/internal/builder"
	"forward/internal/config"
	_ "forward/internal/handler/http"
	_ "forward/internal/listener/h3"
	"forward/internal/metadata"

	_ "unsafe"
)

//go:linkname httpRedactURL forward/internal/handler/http.redactURL
func httpRedactURL(u *url.URL) string

//go:linkname builderBuildHysteria2DialerMetadata forward/internal/builder.buildHysteria2DialerMetadata
func builderBuildHysteria2DialerMetadata(hop endpoint.Endpoint, cfgInsecure bool) metadata.Metadata

//go:linkname builderResolveTypes forward/internal/builder.resolveTypes
func builderResolveTypes(scheme string) (connectorName, dialerName string, err error)

//go:linkname appShouldWarmup forward/base/app.shouldWarmup
func appShouldWarmup(cfg config.Config) bool

//go:linkname h3CleanupTickInterval forward/internal/listener/h3.cleanupTickInterval
var h3CleanupTickInterval time.Duration

//go:linkname h3SessionIdleTimeout forward/internal/listener/h3.sessionIdleTimeout
var h3SessionIdleTimeout time.Duration
