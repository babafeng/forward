package tests

import (
	"bytes"
	"strings"
	"testing"

	"forward/base/logging"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input   string
		want    logging.Level
		wantErr bool
	}{
		{"debug", logging.LevelDebug, false},
		{"DEBUG", logging.LevelDebug, false},
		{"info", logging.LevelInfo, false},
		{"warn", logging.LevelWarn, false},
		{"error", logging.LevelError, false},
		{"off", logging.LevelOff, false},
		{"silent", logging.LevelOff, false},
		{"none", logging.LevelOff, false},
		{"", logging.LevelInfo, false},
		{"invalid", logging.LevelInfo, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := logging.ParseLevel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		level logging.Level
		want  string
	}{
		{logging.LevelDebug, "debug"},
		{logging.LevelInfo, "info"},
		{logging.LevelWarn, "warn"},
		{logging.LevelError, "error"},
		{logging.LevelOff, "off"},
		{logging.Level(100), "Level(100)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.level.String(); got != tt.want {
				t.Errorf("Level.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoggerLevelGetSet(t *testing.T) {
	log := logging.New(logging.Options{Level: logging.LevelInfo})

	if log.Level() != logging.LevelInfo {
		t.Errorf("initial Level() = %v, want LevelInfo", log.Level())
	}

	log.SetLevel(logging.LevelDebug)
	if log.Level() != logging.LevelDebug {
		t.Errorf("after SetLevel, Level() = %v, want LevelDebug", log.Level())
	}
}

func TestLoggerOutput(t *testing.T) {
	var buf bytes.Buffer
	log := logging.New(logging.Options{
		Level: logging.LevelInfo,
		Out:   &buf,
		Err:   &buf,
	})

	log.Info("test message %d", 42)

	output := buf.String()
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("output should contain [INFO], got: %s", output)
	}
	if !strings.Contains(output, "test message 42") {
		t.Errorf("output should contain message, got: %s", output)
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log := logging.New(logging.Options{
		Level: logging.LevelWarn,
		Out:   &buf,
		Err:   &buf,
	})

	log.Debug("debug message")
	log.Info("info message")
	log.Warn("warn message")

	output := buf.String()
	if strings.Contains(output, "debug message") {
		t.Error("debug message should be filtered")
	}
	if strings.Contains(output, "info message") {
		t.Error("info message should be filtered")
	}
	if !strings.Contains(output, "warn message") {
		t.Error("warn message should be present")
	}
}

func TestLoggerLevelOff(t *testing.T) {
	var buf bytes.Buffer
	log := logging.New(logging.Options{
		Level: logging.LevelOff,
		Out:   &buf,
		Err:   &buf,
	})

	log.Debug("debug")
	log.Info("info")
	log.Warn("warn")
	log.Error("error")

	if buf.Len() > 0 {
		t.Errorf("LevelOff should suppress all output, got: %s", buf.String())
	}
}
