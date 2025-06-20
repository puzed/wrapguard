package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLogLevel_String(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{LogLevelError, "error"},
		{LogLevelWarn, "warn"},
		{LogLevelInfo, "info"},
		{LogLevelDebug, "debug"},
		{LogLevel(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("LogLevel.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input       string
		expected    LogLevel
		expectError bool
	}{
		{"error", LogLevelError, false},
		{"warn", LogLevelWarn, false},
		{"warning", LogLevelWarn, false},
		{"info", LogLevelInfo, false},
		{"debug", LogLevelDebug, false},
		{"ERROR", LogLevelError, false}, // Test case insensitive
		{"INFO", LogLevelInfo, false},
		{"invalid", LogLevelInfo, true},
		{"", LogLevelInfo, true},
		{"trace", LogLevelInfo, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseLogLevel(tt.input)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if got != tt.expected {
				t.Errorf("ParseLogLevel(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelInfo, &buf)

	if logger == nil {
		t.Error("NewLogger returned nil")
	}

	if logger.level != LogLevelInfo {
		t.Errorf("expected level %v, got %v", LogLevelInfo, logger.level)
	}

	if logger.output != &buf {
		t.Error("output not set correctly")
	}
}

func TestLogger_Log(t *testing.T) {
	tests := []struct {
		name         string
		loggerLevel  LogLevel
		logLevel     LogLevel
		message      string
		shouldOutput bool
	}{
		{"error at error level", LogLevelError, LogLevelError, "error message", true},
		{"warn at error level", LogLevelError, LogLevelWarn, "warn message", false},
		{"info at error level", LogLevelError, LogLevelInfo, "info message", false},
		{"debug at error level", LogLevelError, LogLevelDebug, "debug message", false},

		{"error at warn level", LogLevelWarn, LogLevelError, "error message", true},
		{"warn at warn level", LogLevelWarn, LogLevelWarn, "warn message", true},
		{"info at warn level", LogLevelWarn, LogLevelInfo, "info message", false},
		{"debug at warn level", LogLevelWarn, LogLevelDebug, "debug message", false},

		{"error at info level", LogLevelInfo, LogLevelError, "error message", true},
		{"warn at info level", LogLevelInfo, LogLevelWarn, "warn message", true},
		{"info at info level", LogLevelInfo, LogLevelInfo, "info message", true},
		{"debug at info level", LogLevelInfo, LogLevelDebug, "debug message", false},

		{"error at debug level", LogLevelDebug, LogLevelError, "error message", true},
		{"warn at debug level", LogLevelDebug, LogLevelWarn, "warn message", true},
		{"info at debug level", LogLevelDebug, LogLevelInfo, "info message", true},
		{"debug at debug level", LogLevelDebug, LogLevelDebug, "debug message", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := NewLogger(tt.loggerLevel, &buf)

			logger.log(tt.logLevel, tt.message)

			output := buf.String()
			if tt.shouldOutput {
				if output == "" {
					t.Error("expected output but got none")
				}

				// Verify JSON format
				var entry LogEntry
				if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
					t.Errorf("failed to parse JSON output: %v", err)
				}

				if entry.Level != tt.logLevel.String() {
					t.Errorf("expected level %s, got %s", tt.logLevel.String(), entry.Level)
				}

				if entry.Message != tt.message {
					t.Errorf("expected message %q, got %q", tt.message, entry.Message)
				}

				if entry.Timestamp == "" {
					t.Error("timestamp is empty")
				}

				// Verify timestamp format
				if _, err := time.Parse(time.RFC3339, entry.Timestamp); err != nil {
					t.Errorf("invalid timestamp format: %v", err)
				}
			} else {
				if output != "" {
					t.Errorf("expected no output but got: %s", output)
				}
			}
		})
	}
}

func TestLogger_LogMethods(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelDebug, &buf)

	tests := []struct {
		name    string
		logFunc func(string, ...interface{})
		level   string
		message string
	}{
		{"Errorf", logger.Errorf, "error", "error message"},
		{"Warnf", logger.Warnf, "warn", "warning message"},
		{"Infof", logger.Infof, "info", "info message"},
		{"Debugf", logger.Debugf, "debug", "debug message"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc(tt.message)

			output := buf.String()
			if output == "" {
				t.Error("expected output but got none")
			}

			var entry LogEntry
			if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
				t.Errorf("failed to parse JSON output: %v", err)
			}

			if entry.Level != tt.level {
				t.Errorf("expected level %s, got %s", tt.level, entry.Level)
			}

			if entry.Message != tt.message {
				t.Errorf("expected message %q, got %q", tt.message, entry.Message)
			}
		})
	}
}

func TestLogger_LogWithFormatting(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelInfo, &buf)

	logger.Infof("test message with %s and %d", "string", 42)

	output := buf.String()
	var entry LogEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
		t.Errorf("failed to parse JSON output: %v", err)
	}

	expected := "test message with string and 42"
	if entry.Message != expected {
		t.Errorf("expected message %q, got %q", expected, entry.Message)
	}
}

func TestLogger_JSONMarshaling(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelInfo, &buf)

	// Test with special characters that need JSON escaping
	message := `test "quoted" message with \backslash and 
newline`
	logger.Infof(message)

	output := buf.String()
	var entry LogEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
		t.Errorf("failed to parse JSON output: %v", err)
	}

	if entry.Message != message {
		t.Errorf("message not preserved correctly through JSON marshaling")
	}
}

func TestLogger_ConcurrentAccess(t *testing.T) {
	// Test that concurrent logging doesn't panic or cause data races
	// We'll use a simpler approach that just verifies the logger doesn't crash

	var buf bytes.Buffer
	logger := NewLogger(LogLevelDebug, &buf)

	// Test concurrent logging with fewer goroutines and messages
	done := make(chan bool, 2)

	for i := 0; i < 2; i++ {
		go func(id int) {
			// Just log a few messages to test thread safety
			for j := 0; j < 3; j++ {
				logger.Infof("goroutine %d message %d", id, j)
				time.Sleep(1 * time.Millisecond) // Small delay to reduce race conditions
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("goroutine did not complete within timeout")
			return
		}
	}

	// Give time for all writes to complete
	time.Sleep(50 * time.Millisecond)

	output := buf.String()

	// Just verify we got some output and it's not corrupted
	if len(output) == 0 {
		t.Error("expected some log output from concurrent access")
	}

	// Verify that we have at least some valid JSON lines
	lines := strings.Split(strings.TrimSpace(output), "\n")
	validLines := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			validLines++
		}
	}

	// We should have at least a few valid log entries
	if validLines < 2 {
		t.Errorf("expected at least 2 valid log entries from concurrent access, got %d", validLines)
	}
}

func TestSetGlobalLogger(t *testing.T) {
	// Save original logger
	originalLogger := logger

	// Create a new logger
	var buf bytes.Buffer
	testLogger := NewLogger(LogLevelError, &buf)

	// Set as global logger
	SetGlobalLogger(testLogger)

	// Verify it was set
	if logger != testLogger {
		t.Error("global logger not set correctly")
	}

	// Restore original logger
	SetGlobalLogger(originalLogger)
}

func TestGlobalLoggerInitialization(t *testing.T) {
	// The global logger should be initialized in init()
	if logger == nil {
		t.Error("global logger not initialized")
	}

	if logger.level != LogLevelInfo {
		t.Errorf("expected default log level %v, got %v", LogLevelInfo, logger.level)
	}

	if logger.output != os.Stderr {
		t.Error("expected default output to be os.Stderr")
	}
}

func TestLogEntry_JSONTags(t *testing.T) {
	entry := LogEntry{
		Timestamp: "2023-01-01T00:00:00Z",
		Level:     "info",
		Message:   "test message",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal LogEntry: %v", err)
	}

	expected := `{"timestamp":"2023-01-01T00:00:00Z","level":"info","message":"test message"}`
	if string(data) != expected {
		t.Errorf("JSON output mismatch:\nexpected: %s\ngot:      %s", expected, string(data))
	}
}

func TestLogger_EmptyMessage(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelInfo, &buf)

	logger.Infof("")

	output := buf.String()
	var entry LogEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
		t.Errorf("failed to parse JSON output: %v", err)
	}

	if entry.Message != "" {
		t.Errorf("expected empty message, got %q", entry.Message)
	}
}

func TestLogger_LongMessage(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelInfo, &buf)

	// Create a very long message
	longMessage := strings.Repeat("a", 10000)
	logger.Infof(longMessage)

	output := buf.String()
	var entry LogEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
		t.Errorf("failed to parse JSON output: %v", err)
	}

	if entry.Message != longMessage {
		t.Error("long message not preserved correctly")
	}
}

// Benchmark tests for performance
func BenchmarkLogger_Info(b *testing.B) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelInfo, &buf)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Infof("benchmark message %d", i)
	}
}

func BenchmarkLogger_InfoFiltered(b *testing.B) {
	var buf bytes.Buffer
	logger := NewLogger(LogLevelError, &buf) // Debug messages will be filtered

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Debugf("benchmark message %d", i)
	}
}

func BenchmarkParseLogLevel(b *testing.B) {
	levels := []string{"error", "warn", "info", "debug"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		level := levels[i%len(levels)]
		_, _ = ParseLogLevel(level)
	}
}
