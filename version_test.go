package main

import (
	"testing"
)

func TestVersion(t *testing.T) {
	// Test that Version is not empty
	if Version == "" {
		t.Error("Version should not be empty")
	}

	// Test that Version has expected default value
	if Version != "v1.0.0-dev" {
		t.Errorf("Expected default version 'v1.0.0-dev', got %s", Version)
	}
}

func TestVersionFormat(t *testing.T) {
	// Test that Version starts with 'v'
	if len(Version) == 0 || Version[0] != 'v' {
		t.Errorf("Version should start with 'v', got %s", Version)
	}

	// Test that Version contains expected components
	if len(Version) < 5 { // At minimum "v1.0.0"
		t.Errorf("Version should be at least 5 characters long, got %s", Version)
	}
}
