package app

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"forward/base/logging"

	xlog "github.com/xtls/xray-core/common/log"
)

type noopXrayHandler struct{}

func (noopXrayHandler) Handle(xlog.Message) {}

func TestMainReturnsZeroOnHelp(t *testing.T) {
	withMainArgs(t, []string{"forward", "-h"}, func() {
		if got := Main(); got != 0 {
			t.Fatalf("Main() = %d, want 0", got)
		}
	})
}

func TestMainReturnsErrorWhenListenerFails(t *testing.T) {
	withMainArgs(t, []string{"forward", "-L", "ftp://127.0.0.1:12345"}, func() {
		if got := Main(); got != 1 {
			t.Fatalf("Main() = %d, want 1", got)
		}
	})
}

func TestRegisterXrayLogHandlerBridgesWarningsWithoutVerbose(t *testing.T) {
	resetXrayLogHandler(t)

	var out bytes.Buffer
	logger := logging.New(logging.Options{
		Level: logging.LevelInfo,
		Out:   &out,
		Err:   &out,
	})

	registerXrayLogHandler(logging.LevelInfo, logger, false)

	xlog.Record(&xlog.GeneralMessage{
		Severity: xlog.Severity_Warning,
		Content:  "warning from xray",
	})
	if got := out.String(); !strings.Contains(got, "warning from xray") {
		t.Fatalf("warning log = %q, want message to be bridged", got)
	}

	out.Reset()
	xlog.Record(&xlog.GeneralMessage{
		Severity: xlog.Severity_Debug,
		Content:  "debug from xray",
	})
	if got := out.String(); got != "" {
		t.Fatalf("debug log = %q, want no output when verbose=false", got)
	}
}

func withMainArgs(t *testing.T, args []string, fn func()) {
	t.Helper()
	resetXrayLogHandler(t)

	oldArgs := os.Args
	os.Args = append([]string(nil), args...)
	t.Cleanup(func() {
		os.Args = oldArgs
	})

	fn()
}

func resetXrayLogHandler(t *testing.T) {
	t.Helper()
	xlog.RegisterHandler(noopXrayHandler{})
}
