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
	currentLevel = LevelInfo
	logger       = log.New(os.Stdout, "", 0)
	mu           sync.Mutex
	wd           string
)

func init() {
	wd, _ = os.Getwd()
}

func SetLevel(level LogLevel) {
	mu.Lock()
	defer mu.Unlock()
	currentLevel = level
}

func formatLog(level string, msg string) string {
	now := time.Now().Format("2006-01-02 15:04:05")
	_, file, line, ok := runtime.Caller(3)
	if !ok {
		file = "???"
		line = 0
	} else {
		file = filepath.Base(file)
	}
	return fmt.Sprintf("%s [%s] %s:%d %s", now, level, file, line, msg)
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
		outputMsg = formatLog("DEBUG", msg)
	case LevelInfo:
		outputMsg = formatLog("INFO", msg)
	case LevelWarn:
		outputMsg = formatLog("WARN", msg)
	case LevelError:
		outputMsg = formatLog("ERROR", msg)
	}

	logger.Println(outputMsg)
}

func Debug(format string, v ...interface{}) {
	output(LevelDebug, fmt.Sprintf(format, v...))
}

func Info(format string, v ...interface{}) {
	output(LevelInfo, fmt.Sprintf(format, v...))
}

func Warn(format string, v ...interface{}) {
	output(LevelWarn, fmt.Sprintf(format, v...))
}

func Error(format string, v ...interface{}) {
	output(LevelError, fmt.Sprintf(format, v...))
}

func Logging(format string, v ...interface{}) {
	output(currentLevel, fmt.Sprintf(format, v...))
}

func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	logger.SetOutput(w)
}
