package main

import (
	"strings"
	"testing"
)

func TestGetVersion(t *testing.T) {
	version := GetVersion()

	if version == "" {
		t.Error("GetVersion() returned empty string")
	}

	if version != Version {
		t.Errorf("GetVersion() = %q, want %q", version, Version)
	}
}

func TestGetFullVersion(t *testing.T) {
	fullVersion := GetFullVersion()

	if fullVersion == "" {
		t.Error("GetFullVersion() returned empty string")
	}

	expected := AppName + " " + Version
	if fullVersion != expected {
		t.Errorf("GetFullVersion() = %q, want %q", fullVersion, expected)
	}
}

func TestVersionConstants(t *testing.T) {
	// Test that version constants are defined
	if Version == "" {
		t.Error("Version constant is empty")
	}

	if AppName == "" {
		t.Error("AppName constant is empty")
	}

	// Test that version follows semantic versioning pattern
	if !strings.Contains(Version, "v") {
		t.Error("Version should start with 'v'")
	}

	// Test that app name is reasonable
	if AppName != "WrapGuard" {
		t.Errorf("AppName = %q, want %q", AppName, "WrapGuard")
	}
}

func TestVersionFormat(t *testing.T) {
	// Test version format (should be something like v1.0.0-dev)
	version := GetVersion()

	if !strings.HasPrefix(version, "v") {
		t.Errorf("Version should start with 'v', got %q", version)
	}

	// Check for development version indicator
	if strings.Contains(version, "dev") {
		if !strings.Contains(version, "-dev") {
			t.Errorf("Development version should contain '-dev', got %q", version)
		}
	}
}

func TestFullVersionFormat(t *testing.T) {
	fullVersion := GetFullVersion()

	// Should contain both app name and version
	if !strings.Contains(fullVersion, AppName) {
		t.Errorf("Full version should contain app name %q, got %q", AppName, fullVersion)
	}

	if !strings.Contains(fullVersion, Version) {
		t.Errorf("Full version should contain version %q, got %q", Version, fullVersion)
	}

	// Should be in format "AppName Version"
	parts := strings.Split(fullVersion, " ")
	if len(parts) != 2 {
		t.Errorf("Full version should have format 'AppName Version', got %q", fullVersion)
	}

	if parts[0] != AppName {
		t.Errorf("First part should be app name %q, got %q", AppName, parts[0])
	}

	if parts[1] != Version {
		t.Errorf("Second part should be version %q, got %q", Version, parts[1])
	}
}

// Test version consistency across the module
func TestVersionModuleConsistency(t *testing.T) {
	// The version module should be internally consistent

	if GetVersion() != Version {
		t.Errorf("GetVersion() != Version constant: %q != %q", GetVersion(), Version)
	}

	expectedFull := AppName + " " + Version
	if GetFullVersion() != expectedFull {
		t.Errorf("GetFullVersion() != expected: %q != %q", GetFullVersion(), expectedFull)
	}
}

// Benchmark tests for performance (though these are simple functions)
func BenchmarkGetVersion(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetVersion()
	}
}

func BenchmarkGetFullVersion(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetFullVersion()
	}
}
