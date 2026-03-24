package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func interceptSourcePath(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test source path")
	}
	return filepath.Join(filepath.Dir(file), "lib", "intercept.c")
}

func TestInjectedLibraryHandshakeAndConnectSmoke(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("unsupported runtime platform for smoke test: %s", runtime.GOOS)
	}

	cc, err := findCCompiler()
	if err != nil {
		t.Skipf("skipping smoke test: %v", err)
	}

	helperDir := t.TempDir()
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	libraryPath := filepath.Join(helperDir, cfg.LibraryName)
	if err := buildInterceptLibraryForTest(t, cc, libraryPath); err != nil {
		t.Fatalf("failed to build intercept library: %v", err)
	}

	helperBinary := filepath.Join(helperDir, "connect-probe")
	if err := buildConnectProbeForTest(t, cc, helperBinary); err != nil {
		t.Fatalf("failed to build connect probe: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ipcServer, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer ipcServer.Close()

	subID, ch := ipcServer.Subscribe()
	defer ipcServer.Unsubscribe(subID)

	socksPort := reserveUnusedPort(t)
	cmd := exec.CommandContext(ctx, helperBinary, "203.0.113.1:443")
	cmd.Env = buildChildEnv(os.Environ(), cfg, libraryPath, ipcServer.SocketPath(), socksPort, false, false)

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Logf("probe exited with %v: %s", err, strings.TrimSpace(string(output)))
	}

	deadline := time.After(5 * time.Second)
	var sawReady bool
	var sawConnect bool
	for !(sawReady && sawConnect) {
		select {
		case msg, ok := <-ch:
			if !ok {
				t.Fatal("ipc subscription closed before expected messages arrived")
			}
			switch msg.Type {
			case "READY":
				sawReady = true
			case "CONNECT":
				sawConnect = true
				if msg.Addr == "" {
					t.Fatal("CONNECT message did not include address")
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for READY and CONNECT messages (ready=%v connect=%v)", sawReady, sawConnect)
		}
	}
}

func TestInjectedLibraryBypassesLocalhostConnects(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("unsupported runtime platform for smoke test: %s", runtime.GOOS)
	}

	cc, err := findCCompiler()
	if err != nil {
		t.Skipf("skipping localhost bypass test: %v", err)
	}

	helperDir := t.TempDir()
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	libraryPath := filepath.Join(helperDir, cfg.LibraryName)
	if err := buildInterceptLibraryForTest(t, cc, libraryPath); err != nil {
		t.Fatalf("failed to build intercept library: %v", err)
	}

	helperBinary := filepath.Join(helperDir, "connect-probe")
	if err := buildConnectProbeForTest(t, cc, helperBinary); err != nil {
		t.Fatalf("failed to build connect probe: %v", err)
	}

	ipcServer, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer ipcServer.Close()

	subID, ch := ipcServer.Subscribe()
	defer ipcServer.Unsubscribe(subID)

	socksPort := reserveUnusedPort(t)
	cmd := exec.Command(helperBinary, "127.0.0.1:9")
	cmd.Env = buildChildEnv(os.Environ(), cfg, libraryPath, ipcServer.SocketPath(), socksPort, false, false)

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Logf("probe exited with %v: %s", err, strings.TrimSpace(string(output)))
	}

	deadline := time.After(2 * time.Second)
	sawReady := false
	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				t.Fatal("ipc subscription closed unexpectedly")
			}
			switch msg.Type {
			case "READY":
				sawReady = true
			case "CONNECT":
				t.Fatalf("localhost connect should not be intercepted, saw CONNECT for %q", msg.Addr)
			}
		case <-deadline:
			if !sawReady {
				t.Fatal("timed out waiting for READY message")
			}
			return
		}
	}
}

func TestInterceptorSourceKeepsUnixDomainConnectsBypassed(t *testing.T) {
	data, err := os.ReadFile(interceptSourcePath(t))
	if err != nil {
		t.Fatalf("failed to read interceptor source: %v", err)
	}

	content := string(data)
	requiredSnippets := []string{
		"if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {",
		"return 0; // Only intercept IP connections",
		"case AF_UNIX:",
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("interceptor source missing expected unix-domain bypass snippet: %q", snippet)
		}
	}
}

func TestInjectedLibraryReportsBindSmoke(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("unsupported runtime platform for smoke test: %s", runtime.GOOS)
	}

	cc, err := findCCompiler()
	if err != nil {
		t.Skipf("skipping bind smoke test: %v", err)
	}

	helperDir := t.TempDir()
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	libraryPath := filepath.Join(helperDir, cfg.LibraryName)
	if err := buildInterceptLibraryForTest(t, cc, libraryPath); err != nil {
		t.Fatalf("failed to build intercept library: %v", err)
	}

	helperBinary := filepath.Join(helperDir, "bind-probe")
	if err := buildBindProbeForTest(t, cc, helperBinary); err != nil {
		t.Fatalf("failed to build bind probe: %v", err)
	}

	ipcServer, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer ipcServer.Close()

	subID, ch := ipcServer.Subscribe()
	defer ipcServer.Unsubscribe(subID)

	socksPort := reserveUnusedPort(t)
	cmd := exec.Command(helperBinary)
	cmd.Env = buildChildEnv(os.Environ(), cfg, libraryPath, ipcServer.SocketPath(), socksPort, false, false)

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bind probe failed: %v: %s", err, strings.TrimSpace(string(output)))
	}

	deadline := time.After(5 * time.Second)
	var sawReady bool
	var sawBind bool
	for !(sawReady && sawBind) {
		select {
		case msg, ok := <-ch:
			if !ok {
				t.Fatal("ipc subscription closed before expected messages arrived")
			}
			switch msg.Type {
			case "READY":
				sawReady = true
			case "BIND":
				sawBind = true
				if msg.Port == 0 {
					t.Fatal("BIND message did not include a concrete port")
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for READY and BIND messages (ready=%v bind=%v)", sawReady, sawBind)
		}
	}
}

func TestInjectedLibraryHandlesNonBlockingConnectSmoke(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("unsupported runtime platform for smoke test: %s", runtime.GOOS)
	}

	cc, err := findCCompiler()
	if err != nil {
		t.Skipf("skipping non-blocking smoke test: %v", err)
	}

	helperDir := t.TempDir()
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	libraryPath := filepath.Join(helperDir, cfg.LibraryName)
	if err := buildInterceptLibraryForTest(t, cc, libraryPath); err != nil {
		t.Fatalf("failed to build intercept library: %v", err)
	}

	helperBinary := filepath.Join(helperDir, "nonblocking-connect-probe")
	if err := buildNonBlockingConnectProbeForTest(t, cc, helperBinary); err != nil {
		t.Fatalf("failed to build non-blocking connect probe: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ipcServer, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer ipcServer.Close()

	subID, ch := ipcServer.Subscribe()
	defer ipcServer.Unsubscribe(subID)

	socksPort := startSOCKSSuccessServer(t)
	cmd := exec.CommandContext(ctx, helperBinary, "203.0.113.1:443")
	cmd.Env = buildChildEnv(os.Environ(), cfg, libraryPath, ipcServer.SocketPath(), socksPort, false, false)

	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("non-blocking connect probe timed out, output: %s", strings.TrimSpace(string(output)))
	}
	if err != nil {
		t.Fatalf("non-blocking probe failed: %v: %s", err, strings.TrimSpace(string(output)))
	}

	deadline := time.After(5 * time.Second)
	var sawReady bool
	var sawConnect bool
	for !(sawReady && sawConnect) {
		select {
		case msg, ok := <-ch:
			if !ok {
				t.Fatal("ipc subscription closed before expected messages arrived")
			}
			switch msg.Type {
			case "READY":
				sawReady = true
			case "CONNECT":
				sawConnect = true
				if msg.Addr == "" {
					t.Fatal("CONNECT message did not include address")
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for READY and CONNECT messages (ready=%v connect=%v)", sawReady, sawConnect)
		}
	}
}

func TestInjectedLibraryVirtualizesGetpeernameAfterSOCKSConnect(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("getpeername virtualization is only exercised on Linux now, runtime=%s", runtime.GOOS)
	}

	cc, err := findCCompiler()
	if err != nil {
		t.Skipf("skipping getpeername virtualization test: %v", err)
	}

	helperDir := t.TempDir()
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	libraryPath := filepath.Join(helperDir, cfg.LibraryName)
	if err := buildInterceptLibraryForTest(t, cc, libraryPath); err != nil {
		t.Fatalf("failed to build intercept library: %v", err)
	}

	helperBinary := filepath.Join(helperDir, "getpeername-probe")
	if err := buildGetPeerNameProbeForTest(t, cc, helperBinary); err != nil {
		t.Fatalf("failed to build getpeername probe: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ipcServer, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer ipcServer.Close()

	subID, ch := ipcServer.Subscribe()
	defer ipcServer.Unsubscribe(subID)

	socksPort := startSOCKSSuccessServer(t)
	cmd := exec.CommandContext(ctx, helperBinary, "203.0.113.1:443")
	cmd.Env = buildChildEnv(os.Environ(), cfg, libraryPath, ipcServer.SocketPath(), socksPort, false, false)

	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("getpeername probe timed out, output: %s", strings.TrimSpace(string(output)))
	}
	if err != nil {
		t.Fatalf("getpeername probe failed: %v: %s", err, strings.TrimSpace(string(output)))
	}

	deadline := time.After(5 * time.Second)
	var sawReady bool
	var sawConnect bool
	for !(sawReady && sawConnect) {
		select {
		case msg, ok := <-ch:
			if !ok {
				t.Fatal("ipc subscription closed before expected messages arrived")
			}
			switch msg.Type {
			case "READY":
				sawReady = true
			case "CONNECT":
				sawConnect = true
			}
		case <-deadline:
			t.Fatalf("timed out waiting for READY and CONNECT messages (ready=%v connect=%v)", sawReady, sawConnect)
		}
	}
}

func TestInterceptorSourceClearsVirtualPeerStateBeforeFallbackConnects(t *testing.T) {
	data, err := os.ReadFile(interceptSourcePath(t))
	if err != nil {
		t.Fatalf("failed to read interceptor source: %v", err)
	}

	content := string(data)
	requiredSnippets := []string{
		"static void forget_virtual_peer(int sockfd)",
		"forget_virtual_peer(sockfd);\n        errno = EHOSTUNREACH;",
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("interceptor source missing expected virtual-peer cleanup snippet: %q", snippet)
		}
	}
	fallbacks := []string{
		"forget_virtual_peer(sockfd);\n#ifdef __APPLE__\n        return raw_connect_call(sockfd, addr, addrlen);",
		"forget_virtual_peer(sockfd);\n#ifdef __APPLE__\n        return raw_connect_call(sockfd, addr, addrlen);\n#else\n        return call_real_connect(sockfd, addr, addrlen);",
	}
	foundFallback := false
	for _, snippet := range fallbacks {
		if strings.Contains(content, snippet) {
			foundFallback = true
			break
		}
	}
	if !foundFallback {
		t.Fatalf("interceptor source missing expected virtual-peer fallback connect cleanup")
	}
}

func TestInterceptorSourceDeclaresMacOSInterpositionEntryPoints(t *testing.T) {
	data, err := os.ReadFile(interceptSourcePath(t))
	if err != nil {
		t.Fatalf("failed to read interceptor source: %v", err)
	}

	content := string(data)
	requiredSnippets := []string{
		"#ifdef __APPLE__",
		"DYLD_INTERPOSE(wrapguard_connect, connect)",
		"DYLD_INTERPOSE(wrapguard_bind, bind)",
		"DYLD_INTERPOSE(wrapguard_connectx, connectx)",
		"DYLD_INTERPOSE(wrapguard_sendto, sendto)",
		"DYLD_INTERPOSE(wrapguard_sendmsg, sendmsg)",
		"return raw_bind_call(sockfd, addr, addrlen);",
		"dlsym(RTLD_NEXT, \"connect\")",
		"dlsym(RTLD_NEXT, \"bind\")",
		"dlsym(RTLD_NEXT, \"getpeername\")",
		"dlsym(RTLD_NEXT, \"connectx\")",
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("interceptor source missing expected macOS interposition snippet: %q", snippet)
		}
	}
}

func TestInterceptorSourceUsesMacOSSafeDebugIPCForQUICSuppression(t *testing.T) {
	data, err := os.ReadFile(interceptSourcePath(t))
	if err != nil {
		t.Fatalf("failed to read interceptor source: %v", err)
	}

	content := string(data)
	requiredSnippets := []string{
		"send_ipc_message(\"DEBUG\"",
		"log_debugf(\"Blocking likely QUIC UDP sendto() to %s\", addr_str);",
		"log_debugf(\"Blocking likely QUIC UDP sendmsg() to %s\", addr_str);",
		"DYLD_INTERPOSE(wrapguard_sendto, sendto)",
		"DYLD_INTERPOSE(wrapguard_sendmsg, sendmsg)",
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("interceptor source missing expected macOS QUIC observability snippet: %q", snippet)
		}
	}
}

func TestInterceptorSourceBlocksConnectedDarwinUDPSendPathsViaPeerLookup(t *testing.T) {
	data, err := os.ReadFile(interceptSourcePath(t))
	if err != nil {
		t.Fatalf("failed to read interceptor source: %v", err)
	}

	content := string(data)
	requiredSnippets := []string{
		"if (target == NULL || target_len < (socklen_t)sizeof(sa_family_t)) {",
		"if (call_real_getpeername(sockfd, (struct sockaddr *)&target_storage, &target_len) != 0) {",
		"if (!should_block_udp_target(target)) {",
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("interceptor source missing expected connected-UDP suppression snippet: %q", snippet)
		}
	}
}

func TestInterceptorSourceKeepsDarwinGetpeernameOutOfTheInterposeTable(t *testing.T) {
	data, err := os.ReadFile(interceptSourcePath(t))
	if err != nil {
		t.Fatalf("failed to read interceptor source: %v", err)
	}

	content := string(data)
	if strings.Contains(content, "DYLD_INTERPOSE(wrapguard_getpeername, getpeername)") {
		t.Fatal("Darwin should not interpose getpeername anymore; that regression breaks browser socket-thread behavior")
	}
	requiredSnippets := []string{
		"#ifndef __APPLE__",
		"int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {",
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("interceptor source missing expected Darwin getpeername guard snippet: %q", snippet)
		}
	}
}

func TestInterceptorSourceKeepsExpectReadyOneShotForDarwinChildren(t *testing.T) {
	data, err := os.ReadFile(interceptSourcePath(t))
	if err != nil {
		t.Fatalf("failed to read interceptor source: %v", err)
	}

	content := string(data)
	requiredSnippets := []string{
		"expect_ready_cached = expect_ready_enabled();",
		"if (expect_ready_cached) {\n        unsetenv(\"WRAPGUARD_EXPECT_READY\");\n    }",
		"if (expect_ready_cached && ipc_path != NULL && socks_port != 0) {\n            send_ipc_message(\"READY\", -1, socks_port, NULL);\n        }",
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("interceptor source missing expected one-shot READY snippet: %q", snippet)
		}
	}
}

func TestInterceptorSourcePreservesErrnoAcrossMacOSDebugIPC(t *testing.T) {
	data, err := os.ReadFile(interceptSourcePath(t))
	if err != nil {
		t.Fatalf("failed to read interceptor source: %v", err)
	}

	content := string(data)
	requiredSnippets := []string{
		"int saved_errno = errno;",
		"send_ipc_message(\"DEBUG\", -1, 0, message);",
		"send_ipc_message(\"ERROR\", -1, 0, message);",
		"errno = saved_errno;",
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("interceptor source missing expected errno-preservation snippet: %q", snippet)
		}
	}
}

func TestInterceptorSourceAvoidsPreMutatingConnectxOutputsBeforeFallback(t *testing.T) {
	data, err := os.ReadFile(interceptSourcePath(t))
	if err != nil {
		t.Fatalf("failed to read interceptor source: %v", err)
	}

	content := string(data)
	requiredSnippets := []string{
		"if (endpoints == NULL || endpoints->sae_dstaddr == NULL || endpoints->sae_dstaddrlen < (socklen_t)sizeof(sa_family_t)) {\n        return call_real_connectx(sockfd, endpoints, associd, flags, iov, iovcnt, len, connid);\n    }",
		"if (len != NULL) {\n        *len = 0;\n    }",
		"if (connid != NULL) {\n        *connid = SAE_CONNID_ANY;\n    }",
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("interceptor source missing expected connectx compatibility snippet: %q", snippet)
		}
	}
}

func TestInterceptorSourcePinsMozillaHelperPassthroughPolicyOnMacOS(t *testing.T) {
	data, err := os.ReadFile(interceptSourcePath(t))
	if err != nil {
		t.Fatalf("failed to read interceptor source: %v", err)
	}

	content := string(data)
	requiredSnippets := []string{
		"#include <crt_externs.h>",
		"static int should_passthrough_mozilla_process(char *const *argv)",
		"if (str_equals(base, \"plugin-container\")) {",
		"if (argc > 1 && str_equals(argv[argc - 1], \"socket\")) {",
		"passthrough_mode_cached = should_passthrough_current_process();",
		"if (passthrough_mode_cached) {",
		"return raw_connect_call(sockfd, addr, addrlen);",
		"return raw_connectx_call(sockfd, endpoints, associd, flags, iov, iovcnt, len, connid);",
		"int suppress_debug_log = addr->sa_family == AF_UNIX && sock_type == SOCK_DGRAM;",
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("interceptor source missing expected Mozilla helper passthrough snippet: %q", snippet)
		}
	}
}

func TestInterceptorSourcePinsVirtualPeerBookkeepingForGetpeername(t *testing.T) {
	data, err := os.ReadFile(interceptSourcePath(t))
	if err != nil {
		t.Fatalf("failed to read interceptor source: %v", err)
	}

	content := string(data)
	requiredSnippets := []string{
		"static int wrapguard_getpeername_impl(int sockfd, struct sockaddr *addr, socklen_t *addrlen)",
		"if (lookup_virtual_peer(sockfd, addr, addrlen)) {",
		"remember_virtual_peer(sockfd, addr, addrlen);",
		"#ifndef __APPLE__",
		"int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {",
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("interceptor source missing expected virtual-peer snippet: %q", snippet)
		}
	}
}

func TestInjectedLibraryBlocksLikelyQUICUDPConnectOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only QUIC suppression smoke test")
	}

	cc, err := findCCompiler()
	if err != nil {
		t.Skipf("skipping UDP suppression smoke test: %v", err)
	}

	helperDir := t.TempDir()
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	libraryPath := filepath.Join(helperDir, cfg.LibraryName)
	if err := buildInterceptLibraryForTest(t, cc, libraryPath); err != nil {
		t.Fatalf("failed to build intercept library: %v", err)
	}

	helperBinary := filepath.Join(helperDir, "udp-connect-probe")
	if err := buildUDPConnectProbeForTest(t, cc, helperBinary); err != nil {
		t.Fatalf("failed to build udp connect probe: %v", err)
	}

	ipcServer, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer ipcServer.Close()

	subID, ch := ipcServer.Subscribe()
	defer ipcServer.Unsubscribe(subID)

	socksPort := reserveUnusedPort(t)
	cmd := exec.Command(helperBinary, "203.0.113.1:443")
	cmd.Env = buildChildEnv(os.Environ(), cfg, libraryPath, ipcServer.SocketPath(), socksPort, false, false)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("udp connect probe failed: %v: %s", err, strings.TrimSpace(string(output)))
	}

	deadline := time.After(2 * time.Second)
	sawReady := false
	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				t.Fatal("ipc subscription closed unexpectedly")
			}
			switch msg.Type {
			case "READY":
				sawReady = true
			case "CONNECT":
				t.Fatalf("UDP/443 connect should not have been tunneled through SOCKS, saw CONNECT for %q", msg.Addr)
			}
		case <-deadline:
			if !sawReady {
				t.Fatal("timed out waiting for READY message")
			}
			return
		}
	}
}

func TestInjectedLibraryInterceptsConnectxOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only connectx smoke test")
	}

	cc, err := findCCompiler()
	if err != nil {
		t.Skipf("skipping connectx smoke test: %v", err)
	}

	helperDir := t.TempDir()
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	libraryPath := filepath.Join(helperDir, cfg.LibraryName)
	if err := buildInterceptLibraryForTest(t, cc, libraryPath); err != nil {
		t.Fatalf("failed to build intercept library: %v", err)
	}

	helperBinary := filepath.Join(helperDir, "connectx-probe")
	if err := buildConnectxProbeForTest(t, cc, helperBinary); err != nil {
		t.Fatalf("failed to build connectx probe: %v", err)
	}

	ipcServer, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer ipcServer.Close()

	subID, ch := ipcServer.Subscribe()
	defer ipcServer.Unsubscribe(subID)

	socksPort := reserveUnusedPort(t)
	cmd := exec.Command(helperBinary, "203.0.113.1:443")
	cmd.Env = buildChildEnv(os.Environ(), cfg, libraryPath, ipcServer.SocketPath(), socksPort, true, false)

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Logf("connectx probe exited with %v: %s", err, strings.TrimSpace(string(output)))
	}

	deadline := time.After(5 * time.Second)
	var sawReady bool
	var sawConnect bool
	for !(sawReady && sawConnect) {
		select {
		case msg, ok := <-ch:
			if !ok {
				t.Fatal("ipc subscription closed before expected messages arrived")
			}
			switch msg.Type {
			case "READY":
				sawReady = true
			case "CONNECT":
				sawConnect = true
				if msg.Addr == "" {
					t.Fatal("CONNECT message did not include address")
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for READY and CONNECT messages from connectx probe (ready=%v connect=%v)", sawReady, sawConnect)
		}
	}
}

func TestInjectedLibraryAppliesMozillaRolePolicyOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only Mozilla role policy smoke test")
	}

	cc, err := findCCompiler()
	if err != nil {
		t.Skipf("skipping Mozilla role policy smoke test: %v", err)
	}

	helperDir := t.TempDir()
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	libraryPath := filepath.Join(helperDir, cfg.LibraryName)
	if err := buildInterceptLibraryForTest(t, cc, libraryPath); err != nil {
		t.Fatalf("failed to build intercept library: %v", err)
	}

	helperBinary := filepath.Join(helperDir, "nonblocking-role-probe")
	if err := buildNonBlockingRoleProbeForTest(t, cc, helperBinary); err != nil {
		t.Fatalf("failed to build non-blocking role probe: %v", err)
	}

	tests := []struct {
		name        string
		linkName    string
		args        []string
		wantConnect bool
	}{
		{
			name:        "socket-process-stays-intercepted",
			linkName:    "plugin-container",
			args:        []string{"203.0.113.1:443", "socket"},
			wantConnect: true,
		},
		{
			name:        "gpu-helper-stays-passthrough",
			linkName:    "gpu-helper",
			args:        []string{"203.0.113.1:443"},
			wantConnect: false,
		},
		{
			name:        "librewolf-main-process-stays-intercepted",
			linkName:    "librewolf",
			args:        []string{"203.0.113.1:443"},
			wantConnect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roleBinary := filepath.Join(helperDir, tt.linkName)
			if err := os.Link(helperBinary, roleBinary); err != nil {
				if err := os.Symlink(helperBinary, roleBinary); err != nil {
					t.Fatalf("failed to create role probe alias: %v / %v", err, err)
				}
			}

			ipcServer, err := NewIPCServer()
			if err != nil {
				t.Fatalf("NewIPCServer failed: %v", err)
			}
			defer ipcServer.Close()

			subID, ch := ipcServer.Subscribe()
			defer ipcServer.Unsubscribe(subID)

			socksPort := startSOCKSSuccessServer(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, roleBinary, tt.args...)
			cmd.Env = buildChildEnv(os.Environ(), cfg, libraryPath, ipcServer.SocketPath(), socksPort, true, false)

			output, err := cmd.CombinedOutput()
			if ctx.Err() == context.DeadlineExceeded {
				t.Fatalf("role probe timed out, output: %s", strings.TrimSpace(string(output)))
			}
			if err != nil {
				t.Fatalf("role probe failed: %v: %s", err, strings.TrimSpace(string(output)))
			}

			deadline := time.After(5 * time.Second)
			sawReady := false
			sawConnect := false
			for {
				select {
				case msg, ok := <-ch:
					if !ok {
						t.Fatal("ipc subscription closed unexpectedly")
					}
					switch msg.Type {
					case "READY":
						sawReady = true
					case "CONNECT":
						sawConnect = true
					}
				case <-deadline:
					if !sawReady {
						t.Fatal("timed out waiting for READY from role probe")
					}
					if sawConnect != tt.wantConnect {
						t.Fatalf("CONNECT visibility mismatch for %s: got %v want %v", tt.linkName, sawConnect, tt.wantConnect)
					}
					return
				}
			}
		})
	}
}

func TestInjectedLibraryStripsMacOSInjectionEnvForDescendantsInCompatMode(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only GUI compatibility smoke test")
	}

	cc, err := findCCompiler()
	if err != nil {
		t.Skipf("skipping GUI compatibility smoke test: %v", err)
	}

	helperDir := t.TempDir()
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	libraryPath := filepath.Join(helperDir, cfg.LibraryName)
	if err := buildInterceptLibraryForTest(t, cc, libraryPath); err != nil {
		t.Fatalf("failed to build intercept library: %v", err)
	}

	envDumpBinary := filepath.Join(helperDir, "env-dump-probe")
	if err := buildEnvDumpProbeForTest(t, cc, envDumpBinary); err != nil {
		t.Fatalf("failed to build env dump probe: %v", err)
	}

	spawnBinary := filepath.Join(helperDir, "spawn-child-probe")
	if err := buildSpawnChildProbeForTest(t, cc, spawnBinary); err != nil {
		t.Fatalf("failed to build spawn child probe: %v", err)
	}

	ipcServer, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer ipcServer.Close()

	subID, ch := ipcServer.Subscribe()
	defer ipcServer.Unsubscribe(subID)

	outputPath := filepath.Join(t.TempDir(), "child-env.txt")
	socksPort := reserveUnusedPort(t)
	cmd := exec.Command(spawnBinary, envDumpBinary, outputPath)
	cmd.Env = buildChildEnv(os.Environ(), cfg, libraryPath, ipcServer.SocketPath(), socksPort, true, true)

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("spawn child probe failed: %v: %s", err, strings.TrimSpace(string(output)))
	}

	sawReady := false
	deadline := time.After(5 * time.Second)
	for !sawReady {
		select {
		case msg, ok := <-ch:
			if !ok {
				t.Fatal("ipc subscription closed before READY arrived")
			}
			if msg.Type == "READY" {
				sawReady = true
			}
		case <-deadline:
			t.Fatal("timed out waiting for READY from injected parent")
		}
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read child env output: %v", err)
	}

	got := string(data)
	for _, key := range []string{
		"DYLD_INSERT_LIBRARIES",
		"DYLD_FORCE_FLAT_NAMESPACE",
		envWrapGuardExpectRDY,
		envWrapGuardIPCPath,
		envWrapGuardSOCKSPort,
		envWrapGuardDebug,
		envWrapGuardDebugIPC,
		envWrapGuardBlockUDP,
		envWrapGuardNoInherit,
	} {
		if strings.Contains(got, key+"=") && !strings.Contains(got, key+"=\n") {
			t.Fatalf("child unexpectedly inherited %s: %q", key, got)
		}
	}
}

func TestInjectedLibrarySuppressesMacOSUDP443SendtoAndSendmsgSmoke(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only QUIC send-path suppression smoke test")
	}

	cc, err := findCCompiler()
	if err != nil {
		t.Skipf("skipping UDP send-path suppression smoke test: %v", err)
	}

	helperDir := t.TempDir()
	cfg, err := currentInjectionConfig()
	if err != nil {
		t.Fatalf("currentInjectionConfig failed: %v", err)
	}

	libraryPath := filepath.Join(helperDir, cfg.LibraryName)
	if err := buildInterceptLibraryForTest(t, cc, libraryPath); err != nil {
		t.Fatalf("failed to build intercept library: %v", err)
	}

	helperBinary := filepath.Join(helperDir, "udp-send-probe")
	if err := buildUDPSendProbeForTest(t, cc, helperBinary); err != nil {
		t.Fatalf("failed to build udp send probe: %v", err)
	}

	for _, mode := range []string{"sendto", "sendmsg", "connected-sendto", "connected-sendmsg"} {
		t.Run(mode, func(t *testing.T) {
			ipcServer, err := NewIPCServer()
			if err != nil {
				t.Fatalf("NewIPCServer failed: %v", err)
			}
			defer ipcServer.Close()

			subID, ch := ipcServer.Subscribe()
			defer ipcServer.Unsubscribe(subID)

			socksPort := reserveUnusedPort(t)
			cmd := exec.Command(helperBinary, "203.0.113.1:443", mode)
			cmd.Env = buildChildEnv(os.Environ(), cfg, libraryPath, ipcServer.SocketPath(), socksPort, true, false)

			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("udp %s probe failed: %v: %s", mode, err, strings.TrimSpace(string(output)))
			}
			if strings.Contains(string(output), "WrapGuard DYLD:") || strings.Contains(string(output), "WrapGuard LD_PRELOAD:") {
				t.Fatalf("udp %s probe should not emit recursive interceptor stderr logging: %s", mode, strings.TrimSpace(string(output)))
			}

			deadline := time.After(5 * time.Second)
			sawReady := false
			sawDebug := false
			for !(sawReady && sawDebug) {
				select {
				case msg, ok := <-ch:
					if !ok {
						t.Fatal("ipc subscription closed before expected messages arrived")
					}
					switch msg.Type {
					case "READY":
						sawReady = true
					case "DEBUG":
						if strings.Contains(msg.Addr, "Blocking likely QUIC UDP") {
							sawDebug = true
						}
					case "CONNECT":
						t.Fatalf("udp %s send path should not emit CONNECT, saw %q", mode, msg.Addr)
					}
				case <-deadline:
					t.Fatalf("timed out waiting for READY and QUIC debug messages for %s (ready=%v debug=%v)", mode, sawReady, sawDebug)
				}
			}
		})
	}
}

func findCCompiler() (string, error) {
	candidates := []string{"cc", "clang", "gcc"}
	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no C compiler found in PATH")
}

func buildInterceptLibraryForTest(t *testing.T, cc, outputPath string) error {
	t.Helper()

	sourcePath := interceptSourcePath(t)
	args := []string{"-Wall", "-Wextra", "-Werror"}
	if runtime.GOOS == "darwin" {
		args = append(args, "-dynamiclib", "-o", outputPath, sourcePath)
	} else {
		args = append(args, "-shared", "-fPIC", "-o", outputPath, sourcePath, "-ldl")
	}

	cmd := exec.Command(cc, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildConnectProbeForTest(t *testing.T, cc, outputPath string) error {
	t.Helper()

	sourcePath := filepath.Join(t.TempDir(), "connect_probe.c")
	source := `#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    char input[256];
    memset(input, 0, sizeof(input));
    strncpy(input, argv[1], sizeof(input) - 1);

    char *sep = strrchr(input, ':');
    if (sep == NULL) {
        return 3;
    }

    *sep = '\0';
    const char *host = input;
    int port = atoi(sep + 1);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 4;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return 5;
    }

    (void)connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
    return 0;
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0644); err != nil {
		return err
	}

	args := []string{"-Wall", "-Wextra", "-Werror"}
	if runtime.GOOS == "darwin" {
		args = append(args, "-Wno-deprecated-declarations")
	}
	args = append(args, "-o", outputPath, sourcePath)
	cmd := exec.Command(cc, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildNonBlockingConnectProbeForTest(t *testing.T, cc, outputPath string) error {
	t.Helper()

	sourcePath := filepath.Join(t.TempDir(), "nonblocking_connect_probe.c")
	source := `#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    char input[256];
    memset(input, 0, sizeof(input));
    strncpy(input, argv[1], sizeof(input) - 1);

    char *sep = strrchr(input, ':');
    if (sep == NULL) {
        return 3;
    }

    *sep = '\0';
    const char *host = input;
    int port = atoi(sep + 1);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 4;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        close(fd);
        return 5;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return 6;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return 7;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != -1 || errno != EINPROGRESS) {
        close(fd);
        return 8;
    }

    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(fd, &writefds);

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    int ready = select(fd + 1, NULL, &writefds, NULL, &timeout);
    if (ready != 1) {
        close(fd);
        return 9;
    }

    int so_error = -1;
    socklen_t so_error_len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) != 0) {
        close(fd);
        return 10;
    }
    if (so_error != 0) {
        close(fd);
        return 11;
    }

    close(fd);
    return 0;
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		return err
	}

	args := []string{"-Wall", "-Wextra", "-Werror"}
	if runtime.GOOS == "darwin" {
		args = append(args, "-Wno-deprecated-declarations")
	}
	args = append(args, "-o", outputPath, sourcePath)
	cmd := exec.Command(cc, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildConnectxProbeForTest(t *testing.T, cc, outputPath string) error {
	t.Helper()

	sourcePath := filepath.Join(t.TempDir(), "connectx_probe.c")
	source := `#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    char input[256];
    memset(input, 0, sizeof(input));
    strncpy(input, argv[1], sizeof(input) - 1);

    char *sep = strrchr(input, ':');
    if (sep == NULL) {
        return 3;
    }

    *sep = '\0';
    const char *host = input;
    int port = atoi(sep + 1);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 4;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return 5;
    }

    sa_endpoints_t endpoints;
    memset(&endpoints, 0, sizeof(endpoints));
    endpoints.sae_dstaddr = (const struct sockaddr *)&addr;
    endpoints.sae_dstaddrlen = sizeof(addr);

    (void)connectx(fd, &endpoints, SAE_ASSOCID_ANY, 0, NULL, 0, NULL, NULL);
    close(fd);
    return 0;
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		return err
	}

	args := []string{"-Wall", "-Wextra", "-Werror"}
	if runtime.GOOS == "darwin" {
		args = append(args, "-Wno-deprecated-declarations")
	}
	args = append(args, "-o", outputPath, sourcePath)
	cmd := exec.Command(cc, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildEnvDumpProbeForTest(t *testing.T, cc, outputPath string) error {
	t.Helper()

	sourcePath := filepath.Join(t.TempDir(), "env_dump_probe.c")
	source := `#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    FILE *fp = fopen(argv[1], "w");
    if (fp == NULL) {
        return 3;
    }

    const char *keys[] = {
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FORCE_FLAT_NAMESPACE",
        "WRAPGUARD_EXPECT_READY",
        "WRAPGUARD_IPC_PATH",
        "WRAPGUARD_SOCKS_PORT",
        "WRAPGUARD_DEBUG",
        "WRAPGUARD_DEBUG_IPC",
        "WRAPGUARD_BLOCK_UDP_443",
        "WRAPGUARD_MACOS_NO_INHERIT",
    };

    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const char *value = getenv(keys[i]);
        fprintf(fp, "%s=%s\n", keys[i], value ? value : "");
    }

    fclose(fp);
    return 0;
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		return err
	}

	cmd := exec.Command(cc, "-Wall", "-Wextra", "-Werror", "-o", outputPath, sourcePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildNonBlockingRoleProbeForTest(t *testing.T, cc, outputPath string) error {
	t.Helper()

	sourcePath := filepath.Join(t.TempDir(), "nonblocking_role_probe.c")
	source := `#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }

    char input[256];
    memset(input, 0, sizeof(input));
    strncpy(input, argv[1], sizeof(input) - 1);

    char *sep = strrchr(input, ':');
    if (sep == NULL) {
        return 3;
    }

    *sep = '\0';
    const char *host = input;
    int port = atoi(sep + 1);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 4;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return 5;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return 6;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 && errno != EINPROGRESS) {
        close(fd);
        return 7;
    }

    close(fd);
    return 0;
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		return err
	}

	cmd := exec.Command(cc, "-Wall", "-Wextra", "-Werror", "-o", outputPath, sourcePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildSpawnChildProbeForTest(t *testing.T, cc, outputPath string) error {
	t.Helper()

	sourcePath := filepath.Join(t.TempDir(), "spawn_child_probe.c")
	source := `#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        return 2;
    }

    char *child_argv[] = {argv[1], argv[2], NULL};
    execv(argv[1], child_argv);
    return 3;
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		return err
	}

	cmd := exec.Command(cc, "-Wall", "-Wextra", "-Werror", "-o", outputPath, sourcePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildGetPeerNameProbeForTest(t *testing.T, cc, outputPath string) error {
	t.Helper()

	sourcePath := filepath.Join(t.TempDir(), "getpeername_probe.c")
	source := `#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    char input[256];
    memset(input, 0, sizeof(input));
    strncpy(input, argv[1], sizeof(input) - 1);

    char *sep = strrchr(input, ':');
    if (sep == NULL) {
        return 3;
    }

    *sep = '\0';
    const char *host = input;
    int port = atoi(sep + 1);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 4;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return 5;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return 6;
    }

    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    socklen_t peer_len = sizeof(peer);
    if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0) {
        close(fd);
        return 7;
    }

    char peer_ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip)) == NULL) {
        close(fd);
        return 8;
    }

    if (strcmp(peer_ip, host) != 0 || ntohs(peer.sin_port) != port) {
        close(fd);
        return 9;
    }

    close(fd);
    return 0;
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		return err
	}

	cmd := exec.Command(cc, "-Wall", "-Wextra", "-Werror", "-o", outputPath, sourcePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildUDPSendProbeForTest(t *testing.T, cc, outputPath string) error {
	t.Helper()

	sourcePath := filepath.Join(t.TempDir(), "udp_send_probe.c")
	source := `#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/uio.h>

static int raw_udp_connect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    return (int)syscall(SYS_connect, fd, addr, addrlen);
}

static int parse_target(const char *input, struct sockaddr_in *addr) {
    char copy[256];
    memset(copy, 0, sizeof(copy));
    strncpy(copy, input, sizeof(copy) - 1);

    char *sep = strrchr(copy, ':');
    if (sep == NULL) {
        return 1;
    }

    *sep = '\0';
    addr->sin_family = AF_INET;
    addr->sin_port = htons(atoi(sep + 1));
    return inet_pton(AF_INET, copy, &addr->sin_addr) == 1 ? 0 : 2;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        return 2;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 4;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    if (parse_target(argv[1], &addr) != 0) {
        close(fd);
        return 5;
    }

    const char *mode = argv[2];
    const char payload[] = "quic";

    if (strcmp(mode, "sendto") == 0) {
        ssize_t sent = sendto(fd, payload, sizeof(payload) - 1, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (sent != -1 || errno != EHOSTUNREACH) {
            close(fd);
            return 6;
        }
    } else if (strcmp(mode, "sendmsg") == 0) {
        struct iovec iov;
        memset(&iov, 0, sizeof(iov));
        iov.iov_base = (void *)payload;
        iov.iov_len = sizeof(payload) - 1;

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = &addr;
        msg.msg_namelen = sizeof(addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ssize_t sent = sendmsg(fd, &msg, 0);
        if (sent != -1 || errno != EHOSTUNREACH) {
            close(fd);
            return 7;
        }
    } else if (strcmp(mode, "connected-sendto") == 0) {
        if (raw_udp_connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            close(fd);
            return 9;
        }

        errno = 0;
        ssize_t sent = sendto(fd, payload, sizeof(payload) - 1, 0, NULL, 0);
        if (sent != -1 || errno != EHOSTUNREACH) {
            close(fd);
            return 10;
        }
    } else if (strcmp(mode, "connected-sendmsg") == 0) {
        if (raw_udp_connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            close(fd);
            return 11;
        }

        struct iovec iov;
        memset(&iov, 0, sizeof(iov));
        iov.iov_base = (void *)payload;
        iov.iov_len = sizeof(payload) - 1;

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        errno = 0;
        ssize_t sent = sendmsg(fd, &msg, 0);
        if (sent != -1 || errno != EHOSTUNREACH) {
            close(fd);
            return 12;
        }
    } else {
        close(fd);
        return 8;
    }

    close(fd);
    return 0;
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		return err
	}

	args := []string{"-Wall", "-Wextra", "-Werror"}
	if runtime.GOOS == "darwin" {
		args = append(args, "-Wno-deprecated-declarations")
	}
	args = append(args, "-o", outputPath, sourcePath)
	cmd := exec.Command(cc, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildBindProbeForTest(t *testing.T, cc, outputPath string) error {
	t.Helper()

	sourcePath := filepath.Join(t.TempDir(), "bind_probe.c")
	source := `#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 2;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return 3;
    }

    if (listen(fd, 1) != 0) {
        close(fd);
        return 4;
    }

    close(fd);
    return 0;
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		return err
	}

	cmd := exec.Command(cc, "-Wall", "-Wextra", "-Werror", "-o", outputPath, sourcePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildUDPConnectProbeForTest(t *testing.T, cc, outputPath string) error {
	t.Helper()

	sourcePath := filepath.Join(t.TempDir(), "udp_connect_probe.c")
	source := `#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    char input[256];
    memset(input, 0, sizeof(input));
    strncpy(input, argv[1], sizeof(input) - 1);

    char *sep = strrchr(input, ':');
    if (sep == NULL) {
        return 3;
    }

    *sep = '\0';
    const char *host = input;
    int port = atoi(sep + 1);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 4;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return 5;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != -1 || errno != EHOSTUNREACH) {
        close(fd);
        return 6;
    }

    close(fd);
    return 0;
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		return err
	}

	cmd := exec.Command(cc, "-Wall", "-Wextra", "-Werror", "-o", outputPath, sourcePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func startSOCKSSuccessServer(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start SOCKS success listener: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if errorsIsClosedConn(err) {
					return
				}
				continue
			}
			go func(conn net.Conn) {
				defer conn.Close()

				header := make([]byte, 3)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
					return
				}

				reqHeader := make([]byte, 4)
				if _, err := io.ReadFull(conn, reqHeader); err != nil {
					return
				}

				var rest int
				switch reqHeader[3] {
				case 0x01:
					rest = 4 + 2
				case 0x03:
					domainLen := make([]byte, 1)
					if _, err := io.ReadFull(conn, domainLen); err != nil {
						return
					}
					rest = int(domainLen[0]) + 2
				case 0x04:
					rest = 16 + 2
				default:
					return
				}

				if rest > 0 {
					payload := make([]byte, rest)
					if _, err := io.ReadFull(conn, payload); err != nil {
						return
					}
				}

				_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x12, 0x34})
			}(conn)
		}
	}()

	return listener.Addr().(*net.TCPAddr).Port
}

func errorsIsClosedConn(err error) bool {
	return err != nil && (err == net.ErrClosed || err == syscall.EINVAL || strings.Contains(err.Error(), "use of closed network connection"))
}

func reserveUnusedPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port: %v", err)
	}
	defer listener.Close()

	return listener.Addr().(*net.TCPAddr).Port
}
