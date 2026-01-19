package reverse

import (
	"log"
	"time"

	"github.com/hashicorp/yamux"

	"forward/base/logging"
)

func NewYamuxConfig(logger *logging.Logger) *yamux.Config {
	conf := yamux.DefaultConfig()
	conf.KeepAliveInterval = 10 * time.Second
	conf.LogOutput = nil
	conf.Logger = log.New(logger.Writer(logging.LevelDebug), "[yamux] ", 0)
	return conf
}

func NextProtosForScheme(scheme string) []string {
	switch scheme {
	case "tls", "https":
		return []string{"h2", "http/1.1"}
	case "quic", "http3":
		return []string{"h3"}
	default:
		return nil
	}
}
