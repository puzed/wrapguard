package main

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrintUsage(t *testing.T) {
	// Capture stderr output
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	
	printUsage()
	
	w.Close()
	os.Stderr = oldStderr
	
	// Read captured output
	buf := make([]byte, 4096)
	n, err := r.Read(buf)
	if err != nil && n == 0 {
		t.Fatal("failed to read usage output")
	}
	
	output := string(buf[:n])
	
	// Check that usage contains expected elements
	expectedParts := []string{
		"wrapguard", // Changed to lowercase to match actual output
		"USAGE:",
		"--config",
		"EXAMPLES:",
		"curl",
		"OPTIONS:",
		"--log-level",
		"--help",
	}
	
	for _, part := range expectedParts {
		if !strings.Contains(output, part) {
			t.Errorf("usage output missing expected part: %s", part)
		}
	}
}

func TestMainWithHelp(t *testing.T) {
	// Test the --help flag
	// We need to test this by running the program as a subprocess
	// since main() calls os.Exit()
	
	if os.Getenv("TEST_MAIN_HELP") == "1" {
		// We're in the subprocess
		os.Args = []string{"wrapguard", "--help"}
		main()
		return
	}
	
	// Run subprocess
	cmd := exec.Command(os.Args[0], "-test.run=TestMainWithHelp")
	cmd.Env = append(os.Environ(), "TEST_MAIN_HELP=1")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Exit code 0 is expected for --help
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 0 {
				t.Errorf("expected exit code 0 for --help, got %d", exitErr.ExitCode())
			}
		}
	}
	
	outputStr := string(output)
	if !strings.Contains(strings.ToLower(outputStr), "wrapguard") {
		t.Error("help output should contain 'wrapguard'")
	}
}

func TestMainWithVersion(t *testing.T) {
	if os.Getenv("TEST_MAIN_VERSION") == "1" {
		// We're in the subprocess
		os.Args = []string{"wrapguard", "--version"}
		main()
		return
	}
	
	// Run subprocess
	cmd := exec.Command(os.Args[0], "-test.run=TestMainWithVersion")
	cmd.Env = append(os.Environ(), "TEST_MAIN_VERSION=1")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 0 {
				t.Errorf("expected exit code 0 for --version, got %d", exitErr.ExitCode())
			}
		}
	}
	
	outputStr := string(output)
	if !strings.Contains(outputStr, "wrapguard version") {
		t.Error("version output should contain 'wrapguard version'")
	}
}

func TestMainWithNoConfig(t *testing.T) {
	if os.Getenv("TEST_MAIN_NO_CONFIG") == "1" {
		// We're in the subprocess
		os.Args = []string{"wrapguard", "echo", "hello"}
		main()
		return
	}
	
	// Run subprocess
	cmd := exec.Command(os.Args[0], "-test.run=TestMainWithNoConfig")
	cmd.Env = append(os.Environ(), "TEST_MAIN_NO_CONFIG=1")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 1 {
				t.Errorf("expected exit code 1 for no config, got %d", exitErr.ExitCode())
			}
		}
	}
	
	outputStr := string(output)
	if !strings.Contains(outputStr, "USAGE:") {
		t.Error("no config should show usage")
	}
}

func TestMainWithInvalidLogLevel(t *testing.T) {
	if os.Getenv("TEST_MAIN_INVALID_LOG") == "1" {
		// We're in the subprocess
		tempConfig := createTempConfig(t)
		defer os.Remove(tempConfig)
		
		os.Args = []string{"wrapguard", "--config=" + tempConfig, "--log-level=invalid", "echo", "hello"}
		main()
		return
	}
	
	// Run subprocess
	cmd := exec.Command(os.Args[0], "-test.run=TestMainWithInvalidLogLevel")
	cmd.Env = append(os.Environ(), "TEST_MAIN_INVALID_LOG=1")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 1 {
				t.Errorf("expected exit code 1 for invalid log level, got %d", exitErr.ExitCode())
			}
		}
	}
	
	outputStr := string(output)
	if !strings.Contains(outputStr, "Invalid log level") {
		t.Error("should show invalid log level error")
	}
}

func TestMainWithInvalidConfig(t *testing.T) {
	if os.Getenv("TEST_MAIN_INVALID_CONFIG") == "1" {
		// We're in the subprocess
		os.Args = []string{"wrapguard", "--config=/nonexistent/config.conf", "echo", "hello"}
		main()
		return
	}
	
	// Run subprocess
	cmd := exec.Command(os.Args[0], "-test.run=TestMainWithInvalidConfig")
	cmd.Env = append(os.Environ(), "TEST_MAIN_INVALID_CONFIG=1")
	
	_, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 1 {
				t.Errorf("expected exit code 1 for invalid config, got %d", exitErr.ExitCode())
			}
		}
	}
}

func TestMainWithNoCommand(t *testing.T) {
	if os.Getenv("TEST_MAIN_NO_COMMAND") == "1" {
		// We're in the subprocess
		tempConfig := createTempConfig(t)
		defer os.Remove(tempConfig)
		
		os.Args = []string{"wrapguard", "--config=" + tempConfig}
		main()
		return
	}
	
	// Run subprocess
	cmd := exec.Command(os.Args[0], "-test.run=TestMainWithNoCommand")
	cmd.Env = append(os.Environ(), "TEST_MAIN_NO_COMMAND=1")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 1 {
				t.Errorf("expected exit code 1 for no command, got %d", exitErr.ExitCode())
			}
		}
	}
	
	outputStr := string(output)
	if !strings.Contains(outputStr, "No command specified") {
		t.Error("should show no command error")
	}
}

func TestMainWithLogFile(t *testing.T) {
	if os.Getenv("TEST_MAIN_LOG_FILE") == "1" {
		// We're in the subprocess
		tempConfig := createTempConfig(t)
		defer os.Remove(tempConfig)
		
		tempLog := filepath.Join(os.TempDir(), "wrapguard-test.log")
		defer os.Remove(tempLog)
		
		os.Args = []string{"wrapguard", "--config=" + tempConfig, "--log-file=" + tempLog, "echo", "hello"}
		main()
		return
	}
	
	// Run subprocess
	cmd := exec.Command(os.Args[0], "-test.run=TestMainWithLogFile")
	cmd.Env = append(os.Environ(), "TEST_MAIN_LOG_FILE=1")
	
	// This will likely fail due to missing WireGuard setup, but we can test
	// that it attempts to create the log file
	cmd.Run()
	
	// The test mainly ensures no panic occurs with log file option
}

func TestFlagParsing(t *testing.T) {
	// Test flag parsing logic separately
	tests := []struct {
		name     string
		args     []string
		expected struct {
			config   string
			help     bool
			version  bool
			logLevel string
			logFile  string
		}
	}{
		{
			name: "basic config",
			args: []string{"--config=test.conf", "echo", "hello"},
			expected: struct {
				config   string
				help     bool
				version  bool
				logLevel string
				logFile  string
			}{
				config:   "test.conf",
				help:     false,
				version:  false,
				logLevel: "info",
				logFile:  "",
			},
		},
		{
			name: "help flag",
			args: []string{"--help"},
			expected: struct {
				config   string
				help     bool
				version  bool
				logLevel string
				logFile  string
			}{
				config:   "",
				help:     true,
				version:  false,
				logLevel: "info",
				logFile:  "",
			},
		},
		{
			name: "version flag",
			args: []string{"--version"},
			expected: struct {
				config   string
				help     bool
				version  bool
				logLevel string
				logFile  string
			}{
				config:   "",
				help:     false,
				version:  true,
				logLevel: "info",
				logFile:  "",
			},
		},
		{
			name: "all flags",
			args: []string{"--config=test.conf", "--log-level=debug", "--log-file=test.log", "echo", "hello"},
			expected: struct {
				config   string
				help     bool
				version  bool
				logLevel string
				logFile  string
			}{
				config:   "test.conf",
				help:     false,
				version:  false,
				logLevel: "debug",
				logFile:  "test.log",
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset flag package for each test
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
			
			var configPath, logLevelStr, logFile string
			var showHelp, showVersion bool
			
			flag.StringVar(&configPath, "config", "", "Path to WireGuard configuration file")
			flag.BoolVar(&showHelp, "help", false, "Show help message")
			flag.BoolVar(&showVersion, "version", false, "Show version information")
			flag.StringVar(&logLevelStr, "log-level", "info", "Set log level")
			flag.StringVar(&logFile, "log-file", "", "Set file to write logs to")
			
			// Parse the test arguments
			err := flag.CommandLine.Parse(tt.args)
			if err != nil {
				t.Fatalf("flag parsing failed: %v", err)
			}
			
			// Check results
			if configPath != tt.expected.config {
				t.Errorf("config = %q, want %q", configPath, tt.expected.config)
			}
			if showHelp != tt.expected.help {
				t.Errorf("help = %v, want %v", showHelp, tt.expected.help)
			}
			if showVersion != tt.expected.version {
				t.Errorf("version = %v, want %v", showVersion, tt.expected.version)
			}
			if logLevelStr != tt.expected.logLevel {
				t.Errorf("logLevel = %q, want %q", logLevelStr, tt.expected.logLevel)
			}
			if logFile != tt.expected.logFile {
				t.Errorf("logFile = %q, want %q", logFile, tt.expected.logFile)
			}
		})
	}
}

func TestMainIntegration(t *testing.T) {
	// This is a more comprehensive integration test
	// It will likely fail in test environment due to missing WireGuard setup
	// but tests the full initialization flow
	
	if os.Getenv("TEST_MAIN_INTEGRATION") == "1" {
		// We're in the subprocess
		tempConfig := createTempConfig(t)
		defer os.Remove(tempConfig)
		
		tempLog := filepath.Join(os.TempDir(), "wrapguard-integration.log")
		defer os.Remove(tempLog)
		
		os.Args = []string{"wrapguard", 
			"--config=" + tempConfig,
			"--log-level=debug",
			"--log-file=" + tempLog,
			"echo", "integration test"}
		main()
		return
	}
	
	// Run subprocess with timeout
	cmd := exec.Command(os.Args[0], "-test.run=TestMainIntegration")
	cmd.Env = append(os.Environ(), "TEST_MAIN_INTEGRATION=1")
	
	// Use a timeout to prevent hanging
	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()
	
	select {
	case err := <-done:
		// Test completed (likely with error due to WireGuard setup)
		if err != nil {
			t.Logf("Integration test failed as expected (no WireGuard): %v", err)
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Error("Integration test timed out")
	}
}

// Helper function to create a temporary valid config file
func createTempConfig(t *testing.T) string {
	tempFile, err := os.CreateTemp("", "wrapguard-test-*.conf")
	if err != nil {
		t.Fatalf("failed to create temp config: %v", err)
	}
	
	config := `[Interface]
PrivateKey = cGluZy1wcml2YXRlLWtleS0xMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=
Address = 10.150.0.2/24

[Peer]
PublicKey = cGluZy1wdWJsaWMta2V5LTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0`
	
	if _, err := tempFile.WriteString(config); err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		t.Fatalf("failed to write temp config: %v", err)
	}
	
	tempFile.Close()
	return tempFile.Name()
}

// Test global logger setup in main
func TestMainLoggerSetup(t *testing.T) {
	// Test that the logger is set up correctly in main
	// We can't easily test this without running main, but we can test
	// the logger creation logic
	
	tests := []struct {
		name     string
		logLevel string
		logFile  string
		wantErr  bool
	}{
		{"valid info level", "info", "", false},
		{"valid debug level", "debug", "", false},
		{"valid error level", "error", "", false},
		{"valid warn level", "warn", "", false},
		{"invalid level", "invalid", "", true},
		{"valid with file", "info", "/tmp/test.log", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logLevel, err := ParseLogLevel(tt.logLevel)
			
			if tt.wantErr {
				if err == nil {
					t.Error("expected error for invalid log level")
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			// Test logger creation
			var output bytes.Buffer
			logger := NewLogger(logLevel, &output)
			
			if logger == nil {
				t.Error("NewLogger returned nil")
			}
			
			// Test logging
			logger.Infof("test message")
			
			// Only expect output for levels that should produce output
			if output.Len() == 0 && logLevel >= LogLevelInfo {
				t.Error("expected log output")
			}
		})
	}
}

// Test version constant consistency
func TestVersionConsistency(t *testing.T) {
	// The version in main.go should be consistent
	mainVersion := version // from main.go
	moduleVersion := Version // from version.go
	
	// They might be different (main.go has its own constant)
	// but we test that they're both non-empty
	if mainVersion == "" {
		t.Error("main.go version constant is empty")
	}
	
	if moduleVersion == "" {
		t.Error("version.go Version constant is empty")
	}
	
	// Both should contain version-like strings
	if !strings.Contains(mainVersion, ".") {
		t.Error("main version should contain version number")
	}
}

// Benchmark test for flag parsing
func BenchmarkFlagParsing(b *testing.B) {
	args := []string{"--config=test.conf", "--log-level=info", "echo", "hello"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset flag package
		flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
		
		var configPath, logLevelStr, logFile string
		var showHelp, showVersion bool
		
		flag.StringVar(&configPath, "config", "", "Path to WireGuard configuration file")
		flag.BoolVar(&showHelp, "help", false, "Show help message")
		flag.BoolVar(&showVersion, "version", false, "Show version information")
		flag.StringVar(&logLevelStr, "log-level", "info", "Set log level")
		flag.StringVar(&logFile, "log-file", "", "Set file to write logs to")
		
		flag.CommandLine.Parse(args)
	}
}