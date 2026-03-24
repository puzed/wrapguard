package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInjectionConfigForGOOS(t *testing.T) {
	tests := []struct {
		goos string
		want injectionConfig
	}{
		{
			goos: "linux",
			want: injectionConfig{
				LibraryName:   "libwrapguard.so",
				LibraryEnvVar: "LD_PRELOAD",
			},
		},
		{
			goos: "darwin",
			want: injectionConfig{
				LibraryName:   "libwrapguard.dylib",
				LibraryEnvVar: "DYLD_INSERT_LIBRARIES",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			got, err := injectionConfigForGOOS(tt.goos)
			if err != nil {
				t.Fatalf("injectionConfigForGOOS(%q) returned error: %v", tt.goos, err)
			}
			if got != tt.want {
				t.Fatalf("injectionConfigForGOOS(%q) = %+v, want %+v", tt.goos, got, tt.want)
			}
		})
	}
}

func TestResolveInjectedLibraryPath(t *testing.T) {
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	tmpDir := t.TempDir()
	execPath := filepath.Join(tmpDir, "wrapguard")
	libPath := filepath.Join(tmpDir, cfg.LibraryName)

	if err := os.WriteFile(libPath, []byte("test"), 0o644); err != nil {
		t.Fatalf("failed to create dummy library: %v", err)
	}

	gotPath, gotCfg, err := resolveInjectedLibraryPath(execPath)
	if err != nil {
		t.Fatalf("resolveInjectedLibraryPath failed: %v", err)
	}

	if gotPath != libPath {
		t.Fatalf("resolveInjectedLibraryPath() path = %q, want %q", gotPath, libPath)
	}
	if gotCfg != cfg {
		t.Fatalf("resolveInjectedLibraryPath() config = %+v, want %+v", gotCfg, cfg)
	}
}

func TestResolveInjectedLibraryPathMissing(t *testing.T) {
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	tmpDir := t.TempDir()
	execPath := filepath.Join(tmpDir, "wrapguard")
	_ = filepath.Join(tmpDir, cfg.LibraryName)

	_, _, err = resolveInjectedLibraryPath(execPath)
	if err == nil {
		t.Fatal("resolveInjectedLibraryPath should fail when the platform library is missing")
	}
	if !strings.Contains(err.Error(), cfg.LibraryName) {
		t.Fatalf("expected missing-library error to mention %q, got %v", cfg.LibraryName, err)
	}
}

func TestResolveInjectedLibraryPathFallsBackToInvokedPathDirectory(t *testing.T) {
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	execDir := t.TempDir()
	execPath := filepath.Join(execDir, "wrapguard")

	pathDir := t.TempDir()
	invokedPath := filepath.Join(pathDir, "wrapguard-on-path")
	libPath := filepath.Join(pathDir, cfg.LibraryName)

	if err := os.WriteFile(invokedPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("failed to create invoked-path fixture: %v", err)
	}
	if err := os.WriteFile(libPath, []byte("test"), 0o644); err != nil {
		t.Fatalf("failed to create dummy library: %v", err)
	}

	oldArgs0 := os.Args[0]
	oldPath := os.Getenv("PATH")
	defer func() {
		os.Args[0] = oldArgs0
		_ = os.Setenv("PATH", oldPath)
	}()

	os.Args[0] = "wrapguard-on-path"
	if err := os.Setenv("PATH", pathDir); err != nil {
		t.Fatalf("failed to update PATH: %v", err)
	}

	gotPath, gotCfg, err := resolveInjectedLibraryPath(execPath)
	if err != nil {
		t.Fatalf("resolveInjectedLibraryPath failed: %v", err)
	}
	if gotPath != libPath {
		t.Fatalf("resolveInjectedLibraryPath() path = %q, want %q", gotPath, libPath)
	}
	if gotCfg != cfg {
		t.Fatalf("resolveInjectedLibraryPath() config = %+v, want %+v", gotCfg, cfg)
	}
}

func TestBuildChildEnvUsesPlatformInjectionVariable(t *testing.T) {
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	got := buildChildEnv(
		[]string{
			"PATH=/usr/bin",
			"DYLD_FORCE_FLAT_NAMESPACE=0",
			"UNRELATED=value",
		},
		cfg,
		"/tmp/"+cfg.LibraryName,
		"/tmp/wrapguard.sock",
		4242,
		true,
		false,
	)

	if _, ok := envValue(got, "PATH"); !ok {
		t.Fatal("PATH should be preserved")
	}
	if value, ok := envValue(got, "UNRELATED"); !ok || value != "value" {
		t.Fatalf("unrelated environment should be preserved, got %q, present=%v", value, ok)
	}
	if value, ok := envValue(got, cfg.LibraryEnvVar); !ok || value != "/tmp/"+cfg.LibraryName {
		t.Fatalf("%s not injected correctly: got %q, present=%v", cfg.LibraryEnvVar, value, ok)
	}
	if value, ok := envValue(got, "WRAPGUARD_IPC_PATH"); !ok || value != "/tmp/wrapguard.sock" {
		t.Fatalf("WRAPGUARD_IPC_PATH not injected correctly: got %q, present=%v", value, ok)
	}
	if value, ok := envValue(got, "WRAPGUARD_SOCKS_PORT"); !ok || value != "4242" {
		t.Fatalf("WRAPGUARD_SOCKS_PORT not injected correctly: got %q, present=%v", value, ok)
	}
	if value, ok := envValue(got, envWrapGuardExpectRDY); !ok || value != "1" {
		t.Fatalf("%s not injected correctly: got %q, present=%v", envWrapGuardExpectRDY, value, ok)
	}
	if cfg.LibraryEnvVar == "DYLD_INSERT_LIBRARIES" {
		if value, ok := envValue(got, envWrapGuardBlockUDP); !ok || value != "1" {
			t.Fatalf("%s should be enabled on macOS, got %q, present=%v", envWrapGuardBlockUDP, value, ok)
		}
		if value, ok := envValue(got, envWrapGuardDebugIPC); !ok || value != "1" {
			t.Fatalf("%s should be enabled for macOS debug launches, got %q, present=%v", envWrapGuardDebugIPC, value, ok)
		}
	} else if _, ok := envValue(got, envWrapGuardBlockUDP); ok {
		t.Fatalf("%s should not be injected on Linux", envWrapGuardBlockUDP)
	} else if _, ok := envValue(got, envWrapGuardDebugIPC); ok {
		t.Fatalf("%s should not be injected on Linux", envWrapGuardDebugIPC)
	} else if _, ok := envValue(got, envWrapGuardNoInherit); ok {
		t.Fatalf("%s should not be injected unless GUI compatibility mode is enabled", envWrapGuardNoInherit)
	}
	if value, ok := envValue(got, "WRAPGUARD_DEBUG"); !ok || value != "1" {
		t.Fatalf("WRAPGUARD_DEBUG should be enabled in debug mode, got %q, present=%v", value, ok)
	}

	if currentPlatformName() == "darwin" {
		if _, ok := envValue(got, "DYLD_FORCE_FLAT_NAMESPACE"); ok {
			t.Fatalf("DYLD_FORCE_FLAT_NAMESPACE should not be injected for Darwin DYLD_INTERPOSE launches")
		}
	} else if value, ok := envValue(got, "DYLD_FORCE_FLAT_NAMESPACE"); !ok || value != "0" {
		t.Fatalf("DYLD_FORCE_FLAT_NAMESPACE should remain unchanged on Linux, got %q, present=%v", value, ok)
	}
}

func TestValidateLaunchTarget(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific launch target validation only applies on Darwin")
	}

	bundlePath, innerExecutable := writeAppBundleFixture(t, "Example")

	details, err := validateLaunchTargetWithLibrary(bundlePath, "")
	if err != nil {
		t.Fatalf("validateLaunchTargetWithLibrary rejected app bundle: %v", err)
	}
	if details == nil {
		t.Fatal("validateLaunchTargetWithLibrary returned nil details for app bundle")
	}
	if details.ResolvedPath != innerExecutable {
		t.Fatalf("validateLaunchTargetWithLibrary resolved %q, want %q", details.ResolvedPath, innerExecutable)
	}
}

func TestResolveAppBundleExecutablePathRejectsMultipleCandidates(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific app bundle resolution only applies on Darwin")
	}

	bundlePath := filepath.Join(t.TempDir(), "Example.app")
	macOSDir := filepath.Join(bundlePath, "Contents", "MacOS")
	if err := os.MkdirAll(macOSDir, 0o755); err != nil {
		t.Fatalf("failed to create app bundle directory: %v", err)
	}

	for _, name := range []string{"First", "Second"} {
		path := filepath.Join(macOSDir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("failed to create executable candidate %s: %v", name, err)
		}
	}

	_, err := resolveAppBundleExecutablePath(bundlePath)
	if err == nil || !strings.Contains(err.Error(), "multiple executable candidates in Contents/MacOS") {
		t.Fatalf("expected multiple-candidate failure, got %v", err)
	}
}

func TestResolveAppBundleExecutablePathRejectsMissingExecutables(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific app bundle resolution only applies on Darwin")
	}

	bundlePath := filepath.Join(t.TempDir(), "Example.app")
	macOSDir := filepath.Join(bundlePath, "Contents", "MacOS")
	if err := os.MkdirAll(macOSDir, 0o755); err != nil {
		t.Fatalf("failed to create app bundle directory: %v", err)
	}

	readmePath := filepath.Join(macOSDir, "README.txt")
	if err := os.WriteFile(readmePath, []byte("not executable"), 0o644); err != nil {
		t.Fatalf("failed to create non-executable file: %v", err)
	}

	_, err := resolveAppBundleExecutablePath(bundlePath)
	if err == nil || !strings.Contains(err.Error(), "does not contain an executable in Contents/MacOS") {
		t.Fatalf("expected missing-executable failure, got %v", err)
	}
}

func TestResolveScriptInterpreter(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/usr/bin/env sh\necho ok\n"), 0o755); err != nil {
		t.Fatalf("failed to create script: %v", err)
	}

	got, ok, err := resolveScriptInterpreter(scriptPath)
	if err != nil {
		t.Fatalf("resolveScriptInterpreter returned error: %v", err)
	}
	if !ok {
		t.Fatal("resolveScriptInterpreter should detect script shebang")
	}

	want, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("failed to resolve sh for test: %v", err)
	}
	if got != want {
		t.Fatalf("resolveScriptInterpreter() = %q, want %q", got, want)
	}
}

func TestResolveScriptInterpreterForBinary(t *testing.T) {
	binaryPath := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(binaryPath, []byte("not a script"), 0o755); err != nil {
		t.Fatalf("failed to create dummy file: %v", err)
	}

	got, ok, err := resolveScriptInterpreter(binaryPath)
	if err != nil {
		t.Fatalf("resolveScriptInterpreter returned error: %v", err)
	}
	if ok {
		t.Fatalf("resolveScriptInterpreter unexpectedly detected interpreter %q", got)
	}
}

func TestValidateLaunchTargetRejectsProtectedInterpreter(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific launch target validation only applies on Darwin")
	}

	scriptPath := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatalf("failed to create script: %v", err)
	}

	if _, err := validateLaunchTargetWithLibrary(scriptPath, ""); err == nil || !strings.Contains(err.Error(), "SIP-protected interpreter") {
		t.Fatalf("expected SIP-protected interpreter rejection, got %v", err)
	}
}

func TestBuildChildEnvMergesExistingInjectionLibraryValue(t *testing.T) {
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	existingValue := "/opt/existing/preload"
	if cfg.LibraryEnvVar == "DYLD_INSERT_LIBRARIES" {
		existingValue = "/opt/existing/a.dylib:/opt/existing/b.dylib"
	}

	got := buildChildEnv(
		[]string{cfg.LibraryEnvVar + "=" + existingValue},
		cfg,
		"/tmp/"+cfg.LibraryName,
		"/tmp/wrapguard.sock",
		4242,
		false,
		false,
	)

	value, ok := envValue(got, cfg.LibraryEnvVar)
	if !ok {
		t.Fatalf("%s not found in child environment", cfg.LibraryEnvVar)
	}
	if !strings.HasPrefix(value, "/tmp/"+cfg.LibraryName) {
		t.Fatalf("%s should prepend wrapguard library, got %q", cfg.LibraryEnvVar, value)
	}
	if !strings.Contains(value, existingValue) {
		t.Fatalf("%s should preserve existing value %q, got %q", cfg.LibraryEnvVar, existingValue, value)
	}
}

func TestBuildChildEnvEnablesMacOSNoInheritWhenRequested(t *testing.T) {
	cfg, err := injectionConfigForGOOS("darwin")
	if err != nil {
		t.Fatalf("injectionConfigForGOOS(darwin) failed: %v", err)
	}

	got := buildChildEnv(
		nil,
		cfg,
		"/tmp/"+cfg.LibraryName,
		"/tmp/wrapguard.sock",
		4242,
		false,
		true,
	)

	if value, ok := envValue(got, envWrapGuardNoInherit); !ok || value != "1" {
		t.Fatalf("%s should be enabled in macOS GUI compatibility mode, got %q, present=%v", envWrapGuardNoInherit, value, ok)
	}
}

func TestBuildChildEnvOverridesInheritedWrapGuardStateOnDarwin(t *testing.T) {
	cfg, err := injectionConfigForGOOS("darwin")
	if err != nil {
		t.Fatalf("injectionConfigForGOOS(darwin) failed: %v", err)
	}

	got := buildChildEnv(
		[]string{
			"DYLD_INSERT_LIBRARIES=/tmp/old-a.dylib:/tmp/old-b.dylib",
			"DYLD_FORCE_FLAT_NAMESPACE=1",
			envWrapGuardIPCPath + "=/tmp/old.sock",
			envWrapGuardSOCKSPort + "=9999",
			envWrapGuardExpectRDY + "=0",
			envWrapGuardDebug + "=0",
			envWrapGuardDebugIPC + "=0",
			envWrapGuardBlockUDP + "=0",
			envWrapGuardNoInherit + "=0",
		},
		cfg,
		"/tmp/"+cfg.LibraryName,
		"/tmp/new.sock",
		4242,
		true,
		true,
	)

	if value, ok := envValue(got, cfg.LibraryEnvVar); !ok || !strings.HasPrefix(value, "/tmp/"+cfg.LibraryName) {
		t.Fatalf("%s should be reinjected with the current dylib first, got %q present=%v", cfg.LibraryEnvVar, value, ok)
	}
	if _, ok := envValue(got, "DYLD_FORCE_FLAT_NAMESPACE"); ok {
		t.Fatal("DYLD_FORCE_FLAT_NAMESPACE should be stripped for Darwin DYLD_INTERPOSE launches")
	}
	if value, ok := envValue(got, envWrapGuardIPCPath); !ok || value != "/tmp/new.sock" {
		t.Fatalf("%s = %q, present=%v, want /tmp/new.sock", envWrapGuardIPCPath, value, ok)
	}
	if value, ok := envValue(got, envWrapGuardSOCKSPort); !ok || value != "4242" {
		t.Fatalf("%s = %q, present=%v, want 4242", envWrapGuardSOCKSPort, value, ok)
	}
	if value, ok := envValue(got, envWrapGuardExpectRDY); !ok || value != "1" {
		t.Fatalf("%s = %q, present=%v, want 1", envWrapGuardExpectRDY, value, ok)
	}
	if value, ok := envValue(got, envWrapGuardDebug); !ok || value != "1" {
		t.Fatalf("%s = %q, present=%v, want 1", envWrapGuardDebug, value, ok)
	}
	if value, ok := envValue(got, envWrapGuardDebugIPC); !ok || value != "1" {
		t.Fatalf("%s = %q, present=%v, want 1", envWrapGuardDebugIPC, value, ok)
	}
	if value, ok := envValue(got, envWrapGuardBlockUDP); !ok || value != "1" {
		t.Fatalf("%s = %q, present=%v, want 1", envWrapGuardBlockUDP, value, ok)
	}
	if value, ok := envValue(got, envWrapGuardNoInherit); !ok || value != "1" {
		t.Fatalf("%s = %q, present=%v, want 1", envWrapGuardNoInherit, value, ok)
	}
}

func TestInitialHandshakeTimeout(t *testing.T) {
	tests := []struct {
		name   string
		goos   string
		target string
		want   string
	}{
		{
			name:   "linux-default",
			goos:   "linux",
			target: "/usr/bin/curl",
			want:   "3s",
		},
		{
			name:   "darwin-cli-default",
			goos:   "darwin",
			target: "/opt/homebrew/bin/curl",
			want:   "3s",
		},
		{
			name:   "darwin-app-bundle",
			goos:   "darwin",
			target: "/Applications/LibreWolf.app",
			want:   "15s",
		},
		{
			name:   "darwin-inner-app-executable",
			goos:   "darwin",
			target: "/Applications/LibreWolf.app/Contents/MacOS/librewolf",
			want:   "15s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := initialHandshakeTimeout(tt.goos, tt.target).String(); got != tt.want {
				t.Fatalf("initialHandshakeTimeout(%q, %q) = %s, want %s", tt.goos, tt.target, got, tt.want)
			}
		})
	}
}

func writeAppBundleFixture(t *testing.T, bundleName string) (string, string) {
	t.Helper()

	sourceExecutable, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatalf("failed to resolve test executable path: %v", err)
	}

	bundlePath := filepath.Join(t.TempDir(), bundleName+".app")
	macOSDir := filepath.Join(bundlePath, "Contents", "MacOS")
	if err := os.MkdirAll(macOSDir, 0o755); err != nil {
		t.Fatalf("failed to create app bundle directory: %v", err)
	}

	innerExecutable := filepath.Join(macOSDir, bundleName)
	sourceData, err := os.ReadFile(sourceExecutable)
	if err != nil {
		t.Fatalf("failed to read source executable: %v", err)
	}
	if err := os.WriteFile(innerExecutable, sourceData, 0o755); err != nil {
		t.Fatalf("failed to write bundle executable: %v", err)
	}

	return bundlePath, innerExecutable
}

func envValue(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return strings.TrimPrefix(kv, prefix), true
		}
	}
	return "", false
}
