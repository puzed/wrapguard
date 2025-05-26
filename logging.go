package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"time"
)

// LogLevel represents the severity of a log message
type LogLevel int

const (
	LogLevelError LogLevel = iota
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
)

// String returns the string representation of the log level
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

// ParseLogLevel parses a string into a LogLevel
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
		return LogLevelInfo, fmt.Errorf("unknown log level: %s", s)
	}
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Component string `json:"component,omitempty"`
}

// Logger provides structured JSON logging
type Logger struct {
	level  LogLevel
	output io.Writer
}

// NewLogger creates a new logger with the specified level and output
func NewLogger(level LogLevel, output io.Writer) *Logger {
	return &Logger{
		level:  level,
		output: output,
	}
}

// shouldLog checks if a message at the given level should be logged
func (l *Logger) shouldLog(level LogLevel) bool {
	return level <= l.level
}

// log writes a log entry to the output
func (l *Logger) log(level LogLevel, component, message string) {
	if !l.shouldLog(level) {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level.String(),
		Message:   message,
		Component: component,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		// Fallback to simple format if JSON marshaling fails
		fmt.Fprintf(l.output, "LOG_ERROR: failed to marshal log entry: %v\n", err)
		return
	}

	fmt.Fprintln(l.output, string(data))
}

// Error logs an error message
func (l *Logger) Error(message string) {
	l.log(LogLevelError, "", message)
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.log(LogLevelError, "", fmt.Sprintf(format, args...))
}

// ErrorWithComponent logs an error message with a component
func (l *Logger) ErrorWithComponent(component, message string) {
	l.log(LogLevelError, component, message)
}

// Warn logs a warning message
func (l *Logger) Warn(message string) {
	l.log(LogLevelWarn, "", message)
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.log(LogLevelWarn, "", fmt.Sprintf(format, args...))
}

// Info logs an info message
func (l *Logger) Info(message string) {
	l.log(LogLevelInfo, "", message)
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, args ...interface{}) {
	l.log(LogLevelInfo, "", fmt.Sprintf(format, args...))
}

// InfoWithComponent logs an info message with a component
func (l *Logger) InfoWithComponent(component, message string) {
	l.log(LogLevelInfo, component, message)
}

// Debug logs a debug message
func (l *Logger) Debug(message string) {
	l.log(LogLevelDebug, "", message)
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.log(LogLevelDebug, "", fmt.Sprintf(format, args...))
}

// DebugWithComponent logs a debug message with a component
func (l *Logger) DebugWithComponent(component, message string) {
	l.log(LogLevelDebug, component, message)
}

// WireGuardLogger creates a logger compatible with WireGuard device logger
func (l *Logger) WireGuardLogger() *log.Logger {
	return log.New(&wireGuardLogWriter{logger: l}, "", 0)
}

// wireGuardLogWriter adapts our Logger to work with standard log.Logger
type wireGuardLogWriter struct {
	logger *Logger
}

func (w *wireGuardLogWriter) Write(p []byte) (n int, err error) {
	message := strings.TrimSpace(string(p))
	if message != "" {
		w.logger.DebugWithComponent("wireguard", message)
	}
	return len(p), nil
}
