package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	currentLevel  = LevelInfo
	logger        = log.New(os.Stdout, "", 0)
	mu            sync.Mutex
	wd            string
	includeCaller bool
)

func init() {
	wd, _ = os.Getwd()
}

func SetLevel(level LogLevel) {
	mu.Lock()
	defer mu.Unlock()
	currentLevel = level
}

func SetCallerEnabled(enabled bool) {
	mu.Lock()
	defer mu.Unlock()
	includeCaller = enabled
}

func shouldLog(level LogLevel) bool {
	mu.Lock()
	defer mu.Unlock()
	return level >= currentLevel
}

func formatLog(level LogLevel, levelLabel string, msg string) string {
	now := time.Now().Format("2006-01-02 15:04:05 -0700 MST")
	if includeCaller || level == LevelDebug {
		_, file, line, ok := runtime.Caller(3)
		if !ok {
			file = "???"
			line = 0
		} else {
			file = filepath.Base(file)
		}
		return fmt.Sprintf("%s [%s] %s:%d %s", now, levelLabel, file, line, msg)
	}
	return fmt.Sprintf("%s [%s] %s", now, levelLabel, msg)
}

func output(level LogLevel, msg string) {
	mu.Lock()
	defer mu.Unlock()

	if level < currentLevel {
		return
	}

	var outputMsg string
	switch level {
	case LevelDebug:
		outputMsg = formatLog(level, "DEBUG", msg)
	case LevelInfo:
		outputMsg = formatLog(level, "INFO", msg)
	case LevelWarn:
		outputMsg = formatLog(level, "WARN", msg)
	case LevelError:
		outputMsg = formatLog(level, "ERROR", msg)
	}

	logger.Println(outputMsg)
}

func Debug(format string, v ...interface{}) {
	if !shouldLog(LevelDebug) {
		return
	}
	output(LevelDebug, fmt.Sprintf(format, v...))
}

func Info(format string, v ...interface{}) {
	if !shouldLog(LevelInfo) {
		return
	}
	output(LevelInfo, fmt.Sprintf(format, v...))
}

func Warn(format string, v ...interface{}) {
	if !shouldLog(LevelWarn) {
		return
	}
	output(LevelWarn, fmt.Sprintf(format, v...))
}

func Error(format string, v ...interface{}) {
	if !shouldLog(LevelError) {
		return
	}
	output(LevelError, fmt.Sprintf(format, v...))
}

func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	logger.SetOutput(w)
}
