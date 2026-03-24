package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBuildChildEnvPropagatesAcrossReexec(t *testing.T) {
	if os.Getenv("TEST_WRAPGUARD_REEXEC_HELPER") == "1" {
		outputPath := os.Getenv("TEST_WRAPGUARD_REEXEC_OUTPUT")
		env := filterEnv(os.Environ(), "TEST_WRAPGUARD_REEXEC_HELPER")
		env = append(env,
			"TEST_WRAPGUARD_REEXEC_GRANDCHILD=1",
			"TEST_WRAPGUARD_REEXEC_OUTPUT="+outputPath,
		)
		if err := syscall.Exec(os.Args[0], []string{os.Args[0], "-test.run=TestBuildChildEnvPropagatesAcrossReexec"}, env); err != nil {
			os.Exit(3)
		}
		return
	}

	if os.Getenv("TEST_WRAPGUARD_REEXEC_GRANDCHILD") == "1" {
		outputPath := os.Getenv("TEST_WRAPGUARD_REEXEC_OUTPUT")
		payload := map[string]string{
			"library": os.Getenv(currentTestInjectionVar()),
			"ipc":     os.Getenv(envWrapGuardIPCPath),
			"socks":   os.Getenv(envWrapGuardSOCKSPort),
			"debug":   os.Getenv(envWrapGuardDebug),
			"debugIP": os.Getenv(envWrapGuardDebugIPC),
			"custom":  os.Getenv("WRAPGUARD_CUSTOM_SENTINEL"),
		}
		data, _ := json.Marshal(payload)
		_ = os.WriteFile(outputPath, data, 0o644)
		return
	}

	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	cc, err := findCCompiler()
	if err != nil {
		t.Skipf("skipping reexec propagation test: %v", err)
	}

	workDir := t.TempDir()
	libraryPath := filepath.Join(workDir, cfg.LibraryName)
	if err := buildInterceptLibraryForTest(t, cc, libraryPath); err != nil {
		t.Fatalf("failed to build intercept library: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "env.json")
	env := buildChildEnv(
		append(os.Environ(), "WRAPGUARD_CUSTOM_SENTINEL=kept"),
		cfg,
		libraryPath,
		filepath.Join(workDir, "wrapguard.sock"),
		45678,
		true,
		false,
	)

	cmd := exec.Command(os.Args[0], "-test.run=TestBuildChildEnvPropagatesAcrossReexec")
	cmd.Env = append(env,
		"TEST_WRAPGUARD_REEXEC_HELPER=1",
		"TEST_WRAPGUARD_REEXEC_OUTPUT="+outputPath,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("reexec helper failed: %v: %s", err, string(output))
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read grandchild env output: %v", err)
	}

	var payload map[string]string
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("failed to decode grandchild env output: %v", err)
	}

	if got := payload["library"]; got != libraryPath {
		t.Fatalf("grandchild %s = %q", cfg.LibraryEnvVar, got)
	}
	if got := payload["ipc"]; got == "" {
		t.Fatal("grandchild missing WRAPGUARD_IPC_PATH")
	}
	if got := payload["socks"]; got != "45678" {
		t.Fatalf("grandchild WRAPGUARD_SOCKS_PORT = %q", got)
	}
	if got := payload["debug"]; got != "1" {
		t.Fatalf("grandchild WRAPGUARD_DEBUG = %q", got)
	}
	if currentPlatformName() == "darwin" {
		if got := payload["debugIP"]; got != "1" {
			t.Fatalf("grandchild %s = %q", envWrapGuardDebugIPC, got)
		}
	} else if got := payload["debugIP"]; got != "" {
		t.Fatalf("grandchild %s should be empty on Linux, got %q", envWrapGuardDebugIPC, got)
	}
	if got := payload["custom"]; got != "kept" {
		t.Fatalf("grandchild custom sentinel = %q", got)
	}
}

func TestBuildChildEnvPropagatesThroughShellChild(t *testing.T) {
	if os.Getenv("TEST_WRAPGUARD_SHELL_ENV_HELPER") == "1" {
		outputPath := os.Getenv("TEST_WRAPGUARD_SHELL_ENV_OUTPUT")
		payload := map[string]string{
			"library": os.Getenv(currentTestInjectionVar()),
			"ipc":     os.Getenv(envWrapGuardIPCPath),
			"socks":   os.Getenv(envWrapGuardSOCKSPort),
			"debug":   os.Getenv(envWrapGuardDebug),
			"debugIP": os.Getenv(envWrapGuardDebugIPC),
			"custom":  os.Getenv("WRAPGUARD_CUSTOM_SENTINEL"),
		}
		data, _ := json.Marshal(payload)
		_ = os.WriteFile(outputPath, data, 0o644)
		return
	}

	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	cc, err := findCCompiler()
	if err != nil {
		t.Skipf("skipping shell propagation test: %v", err)
	}

	workDir := t.TempDir()
	libraryPath := filepath.Join(workDir, cfg.LibraryName)
	if err := buildInterceptLibraryForTest(t, cc, libraryPath); err != nil {
		t.Fatalf("failed to build intercept library: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "shell-env.json")
	env := buildChildEnv(
		append(os.Environ(), "WRAPGUARD_CUSTOM_SENTINEL=kept"),
		cfg,
		libraryPath,
		filepath.Join(workDir, "wrapguard.sock"),
		34567,
		true,
		false,
	)

	shellPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("shell not available")
	}
	if runtime.GOOS == "darwin" {
		if err := validateLaunchTarget(shellPath); err != nil {
			t.Skipf("skipping shell propagation test for protected shell %s: %v", shellPath, err)
		}
	}

	cmd := exec.Command(shellPath, "-c", `exec "$1" -test.run=TestBuildChildEnvPropagatesThroughShellChild`, "wrapguard-shell-test", os.Args[0])
	cmd.Env = append(env,
		"TEST_WRAPGUARD_SHELL_ENV_HELPER=1",
		"TEST_WRAPGUARD_SHELL_ENV_OUTPUT="+outputPath,
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shell helper failed: %v: %s", err, string(output))
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read shell env output: %v", err)
	}

	var payload map[string]string
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("failed to decode shell env output: %v", err)
	}

	if got := payload["library"]; got != libraryPath {
		t.Fatalf("shell child %s = %q", cfg.LibraryEnvVar, got)
	}
	if got := payload["ipc"]; got == "" {
		t.Fatal("shell child missing WRAPGUARD_IPC_PATH")
	}
	if got := payload["socks"]; got != "34567" {
		t.Fatalf("shell child WRAPGUARD_SOCKS_PORT = %q", got)
	}
	if got := payload["debug"]; got != "1" {
		t.Fatalf("shell child WRAPGUARD_DEBUG = %q", got)
	}
	if currentPlatformName() == "darwin" {
		if got := payload["debugIP"]; got != "1" {
			t.Fatalf("shell child %s = %q", envWrapGuardDebugIPC, got)
		}
	} else if got := payload["debugIP"]; got != "" {
		t.Fatalf("shell child %s should be empty on Linux, got %q", envWrapGuardDebugIPC, got)
	}
	if got := payload["custom"]; got != "kept" {
		t.Fatalf("shell child custom sentinel = %q", got)
	}
}

func TestRunDoctorReportsLocalPreflightWithoutLaunchTarget(t *testing.T) {
	execPath := writeDoctorRuntimeFixture(t, true)

	var output bytes.Buffer
	if exitCode := runDoctor(execPath, "", &output); exitCode != 0 {
		t.Fatalf("runDoctor exit code = %d, want 0", exitCode)
	}

	got := output.String()
	if !strings.Contains(got, "doctor: platform=") {
		t.Fatalf("runDoctor output missing platform summary: %q", got)
	}
	if !strings.Contains(got, "doctor: no launch target supplied; preflight completed for local runtime artifacts only") {
		t.Fatalf("runDoctor output missing no-target preflight message: %q", got)
	}
}

func TestRunDoctorReportsMissingRuntimeLibrary(t *testing.T) {
	execPath := writeDoctorRuntimeFixture(t, false)

	var output bytes.Buffer
	if exitCode := runDoctor(execPath, "", &output); exitCode != 1 {
		t.Fatalf("runDoctor exit code = %d, want 1", exitCode)
	}

	got := output.String()
	if !strings.Contains(got, "doctor: runtime library check failed:") {
		t.Fatalf("runDoctor output missing runtime library failure: %q", got)
	}
}

func TestRunDoctorReportsMissingLaunchTarget(t *testing.T) {
	execPath := writeDoctorRuntimeFixture(t, true)

	var output bytes.Buffer
	if exitCode := runDoctor(execPath, "definitely-not-a-real-wrapguard-target", &output); exitCode != 1 {
		t.Fatalf("runDoctor exit code = %d, want 1", exitCode)
	}

	got := output.String()
	if !strings.Contains(got, "doctor: target lookup failed:") && !strings.Contains(got, "doctor: launch target unsupported: failed to resolve launch target") {
		t.Fatalf("runDoctor output missing launch-target lookup failure: %q", got)
	}
}

func TestRunDoctorAcceptsDirectExecutableLaunchTarget(t *testing.T) {
	var execPath string
	if runtime.GOOS == "darwin" {
		binaryPath, err := filepath.Abs("wrapguard")
		if err != nil {
			t.Fatalf("failed to resolve bundled wrapguard path: %v", err)
		}
		if _, err := os.Stat(binaryPath); err != nil {
			t.Skipf("skipping bundled-runtime doctor test: %v", err)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(binaryPath), "libwrapguard.dylib")); err != nil {
			t.Skipf("skipping bundled-runtime doctor test: %v", err)
		}
		execPath = binaryPath
	} else {
		execPath = writeDoctorRuntimeFixture(t, true)
	}

	target, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatalf("failed to resolve test binary path: %v", err)
	}

	var output bytes.Buffer
	if exitCode := runDoctor(execPath, target, &output); exitCode != 0 {
		t.Fatalf("runDoctor exit code = %d, want 0; output=%q", exitCode, output.String())
	}

	got := output.String()
	if !strings.Contains(got, "doctor: target=") {
		t.Fatalf("runDoctor output missing target summary: %q", got)
	}
	if !strings.Contains(got, "doctor: launch target passed preflight") {
		t.Fatalf("runDoctor output missing success message: %q", got)
	}
}

func TestRunDoctorLaunchTargetsOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific launch target validation only applies on Darwin")
	}

	execPath := writeDoctorRuntimeFixture(t, true)
	appTarget, _ := writeAppBundleFixture(t, "Example")

	tests := []struct {
		name     string
		target   string
		want     string
		exitCode int
	}{
		{
			name:     "sip-protected-shell",
			target:   "/bin/sh",
			want:     "doctor: launch target unsupported:",
			exitCode: 1,
		},
		{
			name:     "app-bundle",
			target:   appTarget,
			want:     "doctor: launch target passed preflight",
			exitCode: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			if exitCode := runDoctor(execPath, tt.target, &output); exitCode != tt.exitCode {
				t.Fatalf("runDoctor exit code = %d, want %d", exitCode, tt.exitCode)
			}

			got := output.String()
			if !strings.Contains(got, tt.want) {
				t.Fatalf("runDoctor output missing expected message: %q", got)
			}
		})
	}
}

func TestReportLaunchTargetSecurityInfoFormatsSigningStates(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(targetPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("failed to create target fixture: %v", err)
	}

	tests := []struct {
		name           string
		codesignOutput string
		exitCode       int
		wantLines      []string
	}{
		{
			name:           "unsigned",
			codesignOutput: "code object is not signed at all\n",
			exitCode:       1,
			wantLines: []string{
				"doctor: target-signing=unsigned",
				"doctor: target-hardened-runtime=disabled",
			},
		},
		{
			name:           "ad-hoc",
			codesignOutput: "Executable=/tmp/target\nIdentifier=wrapguard.test\nSignature=adhoc\n",
			exitCode:       0,
			wantLines: []string{
				"doctor: target-signing=ad-hoc",
				"doctor: target-hardened-runtime=disabled",
			},
		},
		{
			name:           "signed-hardened-runtime",
			codesignOutput: "Executable=/tmp/target\nAuthority=Developer ID Application: Example (ABCDE12345)\nflags=0x10000(runtime)\n",
			exitCode:       0,
			wantLines: []string{
				"doctor: target-signing=signed",
				"doctor: target-hardened-runtime=enabled",
				"doctor: advisory: DYLD injection may still be rejected at runtime by the target's hardened runtime policy",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codesignPath := writeCodesignFixture(t, tt.codesignOutput, tt.exitCode)

			var output bytes.Buffer
			if err := reportLaunchTargetSecurityInfo(&output, targetPath, codesignPath); err != nil {
				t.Fatalf("reportLaunchTargetSecurityInfo returned error: %v", err)
			}

			got := output.String()
			for _, wantLine := range tt.wantLines {
				if !strings.Contains(got, wantLine) {
					t.Fatalf("reportLaunchTargetSecurityInfo output missing %q: %q", wantLine, got)
				}
			}
		})
	}
}

func TestReportLaunchTargetSecurityInfoFallsBackWhenCodesignMissing(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(targetPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("failed to create target fixture: %v", err)
	}

	var output bytes.Buffer
	missingCodesign := filepath.Join(t.TempDir(), "missing-codesign")
	if err := reportLaunchTargetSecurityInfo(&output, targetPath, missingCodesign); err == nil {
		t.Fatal("expected reportLaunchTargetSecurityInfo to fail when codesign is missing")
	}

	got := output.String()
	if !strings.Contains(got, "doctor: target-signing=unknown") {
		t.Fatalf("fallback output missing signing status: %q", got)
	}
	if !strings.Contains(got, "doctor: target-hardened-runtime=unknown") {
		t.Fatalf("fallback output missing hardened runtime status: %q", got)
	}
}

func TestWaitForWrappedCommandForwardsSignal(t *testing.T) {
	if os.Getenv("TEST_WRAPGUARD_SIGNAL_HELPER") == "1" {
		runSignalHelper(os.Getenv("TEST_WRAPGUARD_SIGNAL_FILE"), os.Getenv("TEST_WRAPGUARD_IGNORE_SIGNAL") == "1")
		return
	}

	oldLogger := logger
	SetGlobalLogger(NewLogger(LogLevelDebug, io.Discard))
	defer SetGlobalLogger(oldLogger)

	signalFile := filepath.Join(t.TempDir(), "signal.txt")
	cmd := exec.Command(os.Args[0], "-test.run=TestWaitForWrappedCommandForwardsSignal")
	cmd.Env = append(os.Environ(),
		"TEST_WRAPGUARD_SIGNAL_HELPER=1",
		"TEST_WRAPGUARD_SIGNAL_FILE="+signalFile,
	)
	cmd.SysProcAttr = childSysProcAttr()
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start signal helper: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	waitForFile(t, signalFile, false)
	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGTERM

	if exitCode := waitForWrappedCommand(cmd, done, sigCh, nil, time.Second); exitCode != 1 {
		t.Fatalf("waitForWrappedCommand exit code = %d, want 1", exitCode)
	}

	waitForFile(t, signalFile, true)
	data, err := os.ReadFile(signalFile)
	if err != nil {
		t.Fatalf("failed to read signal file: %v", err)
	}
	if string(data) != "terminated:terminated\n" {
		t.Fatalf("signal helper output = %q", string(data))
	}
}

func TestWaitForWrappedCommandKillsHungChildAfterGracePeriod(t *testing.T) {
	if os.Getenv("TEST_WRAPGUARD_SIGNAL_HELPER") == "1" {
		runSignalHelper(os.Getenv("TEST_WRAPGUARD_SIGNAL_FILE"), os.Getenv("TEST_WRAPGUARD_IGNORE_SIGNAL") == "1")
		return
	}

	oldLogger := logger
	SetGlobalLogger(NewLogger(LogLevelDebug, io.Discard))
	defer SetGlobalLogger(oldLogger)

	signalFile := filepath.Join(t.TempDir(), "signal.txt")
	cmd := exec.Command(os.Args[0], "-test.run=TestWaitForWrappedCommandKillsHungChildAfterGracePeriod")
	cmd.Env = append(os.Environ(),
		"TEST_WRAPGUARD_SIGNAL_HELPER=1",
		"TEST_WRAPGUARD_SIGNAL_FILE="+signalFile,
		"TEST_WRAPGUARD_IGNORE_SIGNAL=1",
	)
	cmd.SysProcAttr = childSysProcAttr()
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start hanging signal helper: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	waitForFile(t, signalFile, false)
	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGTERM

	if exitCode := waitForWrappedCommand(cmd, done, sigCh, nil, 200*time.Millisecond); exitCode != 1 {
		t.Fatalf("waitForWrappedCommand exit code = %d, want 1", exitCode)
	}

	waitForFile(t, signalFile, true)
}

func currentTestInjectionVar() string {
	cfg, err := currentInjectionConfig()
	if err != nil {
		return ""
	}
	return cfg.LibraryEnvVar
}

func writeCodesignFixture(t *testing.T, stdout string, exitCode int) string {
	t.Helper()

	scriptPath := filepath.Join(t.TempDir(), "codesign")
	script := "#!/bin/sh\ncat <<'EOF'\n" + stdout + "EOF\nexit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to create codesign fixture: %v", err)
	}
	return scriptPath
}

func runSignalHelper(signalFile string, ignore bool) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)

	_ = os.WriteFile(signalFile, []byte("ready\n"), 0o644)
	sig := <-sigs
	_ = os.WriteFile(signalFile, []byte("terminated:"+sig.String()+"\n"), 0o644)
	if ignore {
		select {}
	}
	os.Exit(0)
}

func waitForFile(t *testing.T, path string, wantTermination bool) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			content := string(data)
			if wantTermination {
				if content != "" && content != "ready\n" {
					return
				}
			} else if content == "ready\n" {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for signal helper file state (termination=%v)", wantTermination)
}

func filterEnv(env []string, dropKey string) []string {
	filtered := make([]string, 0, len(env))
	prefix := dropKey + "="
	for _, entry := range env {
		if len(entry) >= len(prefix) && entry[:len(prefix)] == prefix {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func TestProbeSOCKSReachabilityFailsWhenPortClosed(t *testing.T) {
	port := reserveUnusedPort(t)

	if err := probeSOCKSReachability(port); err == nil {
		t.Fatal("expected probeSOCKSReachability to fail for a closed port")
	}
}

func TestProbeSOCKSReachabilitySucceedsAgainstSOCKSListener(t *testing.T) {
	tunnel := &Tunnel{ourIP: mustParseIPAddr("10.150.0.2")}
	server, err := NewSOCKS5Server(tunnel)
	if err != nil {
		t.Fatalf("NewSOCKS5Server failed: %v", err)
	}
	defer server.Close()

	if err := probeSOCKSReachability(server.Port()); err != nil {
		t.Fatalf("probeSOCKSReachability failed: %v", err)
	}
}

func TestProbeIPCReachabilityFailsWhenSocketMissing(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "missing.sock")
	if err := probeIPCReachability(socketPath); err == nil {
		t.Fatal("expected probeIPCReachability to fail for a missing socket")
	}
}

func TestProbeIPCReachabilitySucceedsForLiveServer(t *testing.T) {
	server, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer server.Close()

	if err := probeIPCReachability(server.SocketPath()); err != nil {
		t.Fatalf("probeIPCReachability failed: %v", err)
	}
}

func TestWaitForIPCMessageReturnsChildExitError(t *testing.T) {
	msgCh := make(chan IPCMessage)
	done := make(chan error, 1)
	done <- errors.New("boom")

	_, err := waitForIPCMessage(msgCh, done, 100*time.Millisecond, "READY")
	if err == nil {
		t.Fatal("expected waitForIPCMessage to return an error")
	}
	if err.Error() != "child exited before READY: boom" {
		t.Fatalf("unexpected waitForIPCMessage error: %v", err)
	}
}

func TestWaitForIPCMessageReturnsMessageBeforeTimeout(t *testing.T) {
	msgCh := make(chan IPCMessage, 1)
	done := make(chan error, 1)
	msgCh <- IPCMessage{Type: "READY", PID: 42}

	msg, err := waitForIPCMessage(msgCh, done, time.Second, "READY")
	if err != nil {
		t.Fatalf("waitForIPCMessage failed: %v", err)
	}
	if msg.PID != 42 {
		t.Fatalf("unexpected PID %d", msg.PID)
	}
}

func TestProbeSOCKSReachabilityRejectsNonSOCKSServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("nope"))
		errCh <- nil
	}()

	if err := probeSOCKSReachability(listener.Addr().(*net.TCPAddr).Port); err == nil {
		t.Fatal("expected probeSOCKSReachability to reject a non-SOCKS server")
	}
	if err := <-errCh; err != nil {
		t.Fatalf("helper server failed: %v", err)
	}
}

func TestRunSelfTestReportsClosedSOCKSListener(t *testing.T) {
	oldLogger := logger
	var output bytes.Buffer
	SetGlobalLogger(NewLogger(LogLevelDebug, &output))
	defer SetGlobalLogger(oldLogger)

	ipcServer, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer ipcServer.Close()

	tunnel := &Tunnel{ourIP: mustParseIPAddr("10.150.0.2")}
	socksServer, err := NewSOCKS5Server(tunnel)
	if err != nil {
		t.Fatalf("NewSOCKS5Server failed: %v", err)
	}
	socksServer.Close()

	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	exitCode := runSelfTest(context.Background(), ipcServer, socksServer, os.Args[0], "", cfg, true)
	if exitCode != 1 {
		t.Fatalf("runSelfTest exit code = %d, want 1", exitCode)
	}

	got := output.String()
	if !strings.Contains(got, "Self-test failed: SOCKS listener is not reachable") {
		t.Fatalf("runSelfTest output missing SOCKS failure diagnostic: %q", got)
	}
}

func writeDoctorRuntimeFixture(t *testing.T, includeLibrary bool) string {
	t.Helper()

	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	workDir := t.TempDir()
	execPath := filepath.Join(workDir, "wrapguard")
	if err := os.WriteFile(execPath, []byte("test"), 0o755); err != nil {
		t.Fatalf("failed to create doctor exec fixture: %v", err)
	}

	if includeLibrary {
		libPath := filepath.Join(workDir, cfg.LibraryName)
		if runtime.GOOS == "darwin" {
			cc, err := findCCompiler()
			if err != nil {
				t.Skipf("skipping doctor fixture test: %v", err)
			}
			if err := buildInterceptLibraryForTest(t, cc, libPath); err != nil {
				t.Fatalf("failed to build doctor library fixture: %v", err)
			}
		} else if err := os.WriteFile(libPath, []byte("test"), 0o644); err != nil {
			t.Fatalf("failed to create doctor library fixture: %v", err)
		}
	}

	return execPath
}
