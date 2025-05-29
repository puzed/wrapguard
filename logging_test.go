package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected LogLevel
		wantErr  bool
	}{
		{"error", LogLevelError, false},
		{"warn", LogLevelWarn, false},
		{"warning", LogLevelWarn, false},
		{"info", LogLevelInfo, false},
		{"debug", LogLevelDebug, false},
		{"ERROR", LogLevelError, false}, // Case insensitive
		{"INFO", LogLevelInfo, false},
		{"invalid", LogLevelInfo, true},
		{"", LogLevelInfo, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			level, err := ParseLogLevel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLogLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && level != tt.expected {
				t.Errorf("ParseLogLevel(%q) = %v, want %v", tt.input, level, tt.expected)
			}
		})
	}
}

func TestLogLevelString(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{LogLevelError, "error"},
		{LogLevelWarn, "warn"},
		{LogLevelInfo, "info"},
		{LogLevelDebug, "debug"},
		{LogLevel(999), "unknown"}, // Invalid level
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.level.String()
			if result != tt.expected {
				t.Errorf("LogLevel(%d).String() = %q, want %q", tt.level, result, tt.expected)
			}
		})
	}
}

func TestLoggerOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelDebug, &buf)

	logger.Error("test error message")

	// Parse the JSON output
	var entry LogEntry
	line := strings.TrimSpace(buf.String())
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("Failed to parse log output as JSON: %v", err)
	}

	if entry.Level != "error" {
		t.Errorf("Expected log level 'error', got %q", entry.Level)
	}
	if entry.Message != "test error message" {
		t.Errorf("Expected message 'test error message', got %q", entry.Message)
	}
	if entry.Timestamp == "" {
		t.Error("Expected timestamp to be set")
	}
}

func TestLoggerLevels(t *testing.T) {
	tests := []struct {
		loggerLevel LogLevel
		logLevel    LogLevel
		shouldLog   bool
	}{
		{LogLevelError, LogLevelError, true},
		{LogLevelError, LogLevelWarn, false},
		{LogLevelWarn, LogLevelError, true},
		{LogLevelWarn, LogLevelWarn, true},
		{LogLevelWarn, LogLevelInfo, false},
		{LogLevelInfo, LogLevelError, true},
		{LogLevelInfo, LogLevelWarn, true},
		{LogLevelInfo, LogLevelInfo, true},
		{LogLevelInfo, LogLevelDebug, false},
		{LogLevelDebug, LogLevelError, true},
		{LogLevelDebug, LogLevelWarn, true},
		{LogLevelDebug, LogLevelInfo, true},
		{LogLevelDebug, LogLevelDebug, true},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			var buf bytes.Buffer
			logger := NewLogger(tt.loggerLevel, &buf)

			// Test the shouldLog method
			result := logger.shouldLog(tt.logLevel)
			if result != tt.shouldLog {
				t.Errorf("shouldLog(%v) with logger level %v = %v, want %v",
					tt.logLevel, tt.loggerLevel, result, tt.shouldLog)
			}

			// Test actual logging
			buf.Reset()
			logger.log(tt.logLevel, "", "test message")

			hasOutput := buf.Len() > 0
			if hasOutput != tt.shouldLog {
				t.Errorf("Expected output: %v, got output: %v", tt.shouldLog, hasOutput)
			}
		})
	}
}

func TestLoggerMethods(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelDebug, &buf)

	tests := []struct {
		name     string
		logFunc  func()
		expected string
	}{
		{
			name:     "Error",
			logFunc:  func() { logger.Error("error message") },
			expected: "error",
		},
		{
			name:     "Errorf",
			logFunc:  func() { logger.Errorf("error %s", "formatted") },
			expected: "error",
		},
		{
			name:     "Warn",
			logFunc:  func() { logger.Warn("warn message") },
			expected: "warn",
		},
		{
			name:     "Warnf",
			logFunc:  func() { logger.Warnf("warn %d", 123) },
			expected: "warn",
		},
		{
			name:     "Info",
			logFunc:  func() { logger.Info("info message") },
			expected: "info",
		},
		{
			name:     "Infof",
			logFunc:  func() { logger.Infof("info %v", true) },
			expected: "info",
		},
		{
			name:     "Debug",
			logFunc:  func() { logger.Debug("debug message") },
			expected: "debug",
		},
		{
			name:     "Debugf",
			logFunc:  func() { logger.Debugf("debug %f", 3.14) },
			expected: "debug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc()

			var entry LogEntry
			line := strings.TrimSpace(buf.String())
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Fatalf("Failed to parse log output as JSON: %v", err)
			}

			if entry.Level != tt.expected {
				t.Errorf("Expected log level %q, got %q", tt.expected, entry.Level)
			}
		})
	}
}

func TestLoggerWithComponent(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelDebug, &buf)

	logger.ErrorWithComponent("test-component", "error message")

	var entry LogEntry
	line := strings.TrimSpace(buf.String())
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("Failed to parse log output as JSON: %v", err)
	}

	if entry.Component != "test-component" {
		t.Errorf("Expected component 'test-component', got %q", entry.Component)
	}
	if entry.Level != "error" {
		t.Errorf("Expected log level 'error', got %q", entry.Level)
	}
	if entry.Message != "error message" {
		t.Errorf("Expected message 'error message', got %q", entry.Message)
	}
}

func TestWireGuardLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelDebug, &buf)

	wgLogger := logger.WireGuardLogger()
	wgLogger.Println("test wireguard message")

	var entry LogEntry
	line := strings.TrimSpace(buf.String())
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("Failed to parse log output as JSON: %v", err)
	}

	if entry.Component != "wireguard" {
		t.Errorf("Expected component 'wireguard', got %q", entry.Component)
	}
	if entry.Level != "debug" {
		t.Errorf("Expected log level 'debug', got %q", entry.Level)
	}
	if !strings.Contains(entry.Message, "test wireguard message") {
		t.Errorf("Expected message to contain 'test wireguard message', got %q", entry.Message)
	}
}

func TestLoggerJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelInfo, &buf)

	logger.Info("test message")

	var entry LogEntry
	line := strings.TrimSpace(buf.String())
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("Failed to parse log output as JSON: %v", err)
	}

	// Validate all required fields are present
	if entry.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
	if entry.Level == "" {
		t.Error("Level should not be empty")
	}
	if entry.Message == "" {
		t.Error("Message should not be empty")
	}

	// Validate timestamp format (RFC3339)
	if !strings.Contains(entry.Timestamp, "T") || !strings.Contains(entry.Timestamp, "Z") {
		t.Errorf("Timestamp should be in RFC3339 format, got %q", entry.Timestamp)
	}
}
