package reverse

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/yamux"

	"forward/base/logging"
)

func NewYamuxConfig(logger *logging.Logger) *yamux.Config {
	conf := yamux.DefaultConfig()
	conf.KeepAliveInterval = 10 * time.Second
	if logger != nil {
		conf.LogOutput = nil
		conf.Logger = &yamuxLogger{logger: logger}
	}
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

type yamuxLogger struct {
	logger *logging.Logger
}

func (l *yamuxLogger) Print(v ...interface{}) {
	l.log(fmt.Sprint(v...))
}

func (l *yamuxLogger) Println(v ...interface{}) {
	l.log(fmt.Sprintln(v...))
}

func (l *yamuxLogger) Printf(format string, v ...interface{}) {
	l.log(fmt.Sprintf(format, v...))
}

func (l *yamuxLogger) log(msg string) {
	if l == nil || l.logger == nil {
		return
	}
	level, text := parseYamuxMessage(msg)
	switch level {
	case logging.LevelError:
		l.logger.Error("%s", text)
	case logging.LevelWarn:
		l.logger.Warn("%s", text)
	case logging.LevelDebug:
		l.logger.Debug("%s", text)
	default:
		l.logger.Info("%s", text)
	}
}

func parseYamuxMessage(msg string) (logging.Level, string) {
	text := strings.TrimSpace(msg)
	level := logging.LevelInfo
	switch {
	case strings.HasPrefix(text, "[ERR]"):
		level = logging.LevelError
		text = strings.TrimSpace(strings.TrimPrefix(text, "[ERR]"))
	case strings.HasPrefix(text, "[WARN]"):
		level = logging.LevelWarn
		text = strings.TrimSpace(strings.TrimPrefix(text, "[WARN]"))
	case strings.HasPrefix(text, "[INFO]"):
		level = logging.LevelInfo
		text = strings.TrimSpace(strings.TrimPrefix(text, "[INFO]"))
	case strings.HasPrefix(text, "[DEBUG]"):
		level = logging.LevelDebug
		text = strings.TrimSpace(strings.TrimPrefix(text, "[DEBUG]"))
	}
	if !strings.HasPrefix(text, "yamux:") {
		text = "yamux: " + text
	}
	return level, text
}
