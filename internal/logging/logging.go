package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
)

type Level int32

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelOff
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	case LevelOff:
		return "off"
	default:
		return fmt.Sprintf("Level(%d)", int(l))
	}
}

func ParseLevel(s string) (Level, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return LevelInfo, nil
	}
	switch s {
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	case "off", "silent", "none":
		return LevelOff, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level: %q", s)
	}
}

type Logger struct {
	level atomic.Int32
	out   *log.Logger
	err   *log.Logger
}

type Options struct {
	Level  Level
	Out    io.Writer
	Err    io.Writer
	Prefix string
	Flags  int
}

func New(opts Options) *Logger {
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}
	err := opts.Err
	if err == nil {
		err = os.Stderr
	}
	flags := opts.Flags
	if flags == 0 {
		flags = log.LstdFlags
	}
	l := &Logger{
		out: log.New(out, opts.Prefix, flags),
		err: log.New(err, opts.Prefix, flags),
	}
	l.level.Store(int32(opts.Level))
	return l
}

func (l *Logger) Level() Level {
	return Level(l.level.Load())
}

func (l *Logger) SetLevel(level Level) {
	l.level.Store(int32(level))
}

func (l *Logger) Debug(format string, args ...any) {
	l.printf(LevelDebug, false, format, args...)
}

func (l *Logger) Info(format string, args ...any) {
	l.printf(LevelInfo, false, format, args...)
}

func (l *Logger) Warn(format string, args ...any) {
	l.printf(LevelWarn, false, format, args...)
}

func (l *Logger) Error(format string, args ...any) {
	l.printf(LevelError, true, format, args...)
}

func (l *Logger) printf(msgLevel Level, isErr bool, format string, args ...any) {
	lvl := Level(l.level.Load())

	if msgLevel < lvl || lvl == LevelOff {
		return
	}

	levelPrefix := fmt.Sprintf("[%s] ", strings.ToUpper(msgLevel.String()))

	// debug 级别时添加文件路径和行号
	if lvl == LevelDebug {
		if _, file, line, ok := runtime.Caller(2); ok {
			file = filepath.Base(file)
			levelPrefix = fmt.Sprintf("[%s] %s:%d ", strings.ToUpper(msgLevel.String()), file, line)
		}
	}

	newFormat := levelPrefix + format

	if isErr {
		l.err.Printf(newFormat, args...)
		return
	}
	l.out.Printf(newFormat, args...)
}
