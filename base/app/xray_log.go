package app

import (
	"fmt"

	"forward/base/logging"

	xlog "github.com/xtls/xray-core/common/log"
)

type xrayLogHandler struct {
	level   string
	logger  *logging.Logger
	verbose bool
}

func registerXrayLogHandler(level logging.Level, logger *logging.Logger, verbose bool) {
	if logger == nil {
		return
	}
	xlog.RegisterHandler(&xrayLogHandler{
		level:   level.String(),
		logger:  logger,
		verbose: verbose,
	})
}

func (h *xrayLogHandler) Handle(msg xlog.Message) {
	var severity xlog.Severity
	var content interface{}

	if gm, ok := msg.(*xlog.GeneralMessage); ok {
		severity = gm.Severity
		content = gm.Content
	} else {
		severity = xlog.Severity_Info
		content = msg.String()
	}

	txt := fmt.Sprint(content)

	switch severity {
	case xlog.Severity_Debug:
		if h.level == "debug" && h.verbose {
			h.logger.Debug("%s", txt)
		}
	case xlog.Severity_Info:
		// Keep xray component chatter opt-in to avoid overwhelming debug logs.
		if h.level == "debug" && h.verbose {
			h.logger.Debug("%s", txt)
		}
	case xlog.Severity_Warning:
		h.logger.Warn("%s", txt)
	case xlog.Severity_Error:
		h.logger.Error("%s", txt)
	default:
		if h.level == "debug" && h.verbose {
			h.logger.Debug("%s", txt)
		}
	}
}
