package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type LogLevel int

const (
	LogLevelError LogLevel = iota
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
)

func (l LogLevel) String() string {
	switch l {
	case LogLevelError:
		return "error"
	case LogLevelWarn:
		return "warn"
	case LogLevelInfo:
		return "info"
	case LogLevelDebug:
		return "debug"
	default:
		return "unknown"
	}
}

func ParseLogLevel(s string) (LogLevel, error) {
	switch strings.ToLower(s) {
	case "error":
		return LogLevelError, nil
	case "warn", "warning":
		return LogLevelWarn, nil
	case "info":
		return LogLevelInfo, nil
	case "debug":
		return LogLevelDebug, nil
	default:
		return LogLevelInfo, fmt.Errorf("invalid log level: %s", s)
	}
}

type Logger struct {
	level  LogLevel
	output io.Writer
	mu     sync.Mutex
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

func NewLogger(level LogLevel, output io.Writer) *Logger {
	return &Logger{
		level:  level,
		output: output,
	}
}

func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level > l.level {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level.String(),
		Message:   fmt.Sprintf(format, args...),
	}

	data, _ := json.Marshal(entry)

	l.mu.Lock()
	fmt.Fprintf(l.output, "%s\n", data)
	l.mu.Unlock()
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l.log(LogLevelError, format, args...)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	l.log(LogLevelWarn, format, args...)
}

func (l *Logger) Infof(format string, args ...interface{}) {
	l.log(LogLevelInfo, format, args...)
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	l.log(LogLevelDebug, format, args...)
}

// Global logger instance
var logger *Logger

func init() {
	// Default logger to stderr with info level
	logger = NewLogger(LogLevelInfo, os.Stderr)
}

func SetGlobalLogger(l *Logger) {
	logger = l
}
