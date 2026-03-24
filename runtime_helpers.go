package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const selfTestProbeTarget = "203.0.113.1:443"

func startIPCEventLogger(ctx context.Context, server *IPCServer, enabled bool) func() {
	if !enabled || server == nil {
		return func() {}
	}

	subID, ch := server.Subscribe()
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				switch msg.Type {
				case "READY":
					logger.Debugf("Interceptor READY from pid %d", msg.PID)
				case "CONNECT":
					logger.Debugf("Interceptor CONNECT from pid %d to %s", msg.PID, msg.Addr)
				case "BIND":
					logger.Debugf("Interceptor BIND from pid %d on port %d", msg.PID, msg.Port)
				case "DEBUG":
					if msg.Detail != "" {
						logger.Debugf("Interceptor DEBUG from pid %d: %s", msg.PID, msg.Detail)
					} else {
						logger.Debugf("Interceptor DEBUG from pid %d addr=%s port=%d", msg.PID, msg.Addr, msg.Port)
					}
				case "UDP_BLOCK":
					logger.Debugf("Interceptor UDP_BLOCK from pid %d to %s (%s)", msg.PID, msg.Addr, msg.Detail)
				case "UDP_SEND":
					logger.Debugf("Interceptor UDP_SEND from pid %d to %s (%s)", msg.PID, msg.Addr, msg.Detail)
				case "ERROR":
					if msg.Detail != "" {
						logger.Warnf("Interceptor ERROR from pid %d: %s", msg.PID, msg.Detail)
					} else {
						logger.Warnf("Interceptor ERROR from pid %d: %s", msg.PID, msg.Addr)
					}
				default:
					logger.Debugf("IPC event %s from pid %d addr=%s port=%d detail=%s", msg.Type, msg.PID, msg.Addr, msg.Port, msg.Detail)
				}
			}
		}
	}()

	return func() {
		server.Unsubscribe(subID)
		<-done
	}
}

func waitForIPCMessage(msgCh <-chan IPCMessage, done <-chan error, timeout time.Duration, wantType string) (IPCMessage, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case msg, ok := <-msgCh:
			if !ok {
				return IPCMessage{}, fmt.Errorf("ipc subscriber closed while waiting for %s", wantType)
			}
			if msg.Type == wantType {
				return msg, nil
			}
		case err := <-done:
			for {
				select {
				case msg, ok := <-msgCh:
					if !ok {
						goto childExit
					}
					if msg.Type == wantType {
						return msg, nil
					}
				default:
					goto childExit
				}
			}
		childExit:
			if err != nil {
				return IPCMessage{}, fmt.Errorf("child exited before %s: %w", wantType, err)
			}
			return IPCMessage{}, fmt.Errorf("child exited before %s", wantType)
		case <-timer.C:
			return IPCMessage{}, fmt.Errorf("timed out waiting for %s", wantType)
		}
	}
}

func waitForWrappedCommand(cmd *exec.Cmd, done <-chan error, sigCh <-chan os.Signal, onTerminate func(), gracePeriod time.Duration) int {
	select {
	case err := <-done:
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				return exitErr.ExitCode()
			}
			logger.Errorf("Child process error: %v", err)
			return 1
		}
		return 0
	case sig := <-sigCh:
		logger.Infof("Received signal %v, shutting down...", sig)
		if onTerminate != nil {
			onTerminate()
		}

		sysSig, ok := sig.(syscall.Signal)
		if !ok {
			sysSig = syscall.SIGTERM
		}
		if err := signalWrappedProcess(cmd, sysSig); err != nil && !errors.Is(err, os.ErrProcessDone) {
			logger.Warnf("Failed to forward signal %v to child: %v", sig, err)
		}

		select {
		case <-done:
		case <-time.After(gracePeriod):
			logger.Warnf("Child process did not exit gracefully, killing...")
			_ = signalWrappedProcess(cmd, syscall.SIGKILL)
			<-done
		}

		return 1
	}
}

func probeIPCReachability(socketPath string) error {
	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

func probeSOCKSReachability(port int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)), time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("unexpected SOCKS version byte %d", reply[0])
	}

	return nil
}

func runDoctor(execPath, launchTarget string, output io.Writer) int {
	if output == nil {
		output = os.Stdout
	}

	libPath, injectCfg, err := resolveInjectedLibraryPath(execPath)
	if err != nil {
		fmt.Fprintf(output, "doctor: runtime library check failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(output, "doctor: platform=%s injection=%s library=%s\n", currentPlatformName(), injectCfg.LibraryEnvVar, libPath)

	if launchTarget == "" {
		fmt.Fprintln(output, "doctor: no launch target supplied; preflight completed for local runtime artifacts only")
		return 0
	}

	resolvedTarget := launchTarget
	var details *launchTargetDetails
	if currentPlatformName() == "darwin" && strings.HasSuffix(launchTarget, ".app") {
		details, err = validateLaunchTargetWithLibrary(launchTarget, libPath)
		if err != nil {
			fmt.Fprintf(output, "doctor: launch target unsupported: %v\n", err)
			return 1
		}
		if details != nil && details.ResolvedPath != "" {
			resolvedTarget = details.ResolvedPath
		}
	} else {
		if lookupPath, err := exec.LookPath(launchTarget); err == nil {
			resolvedTarget = lookupPath
		} else {
			fmt.Fprintf(output, "doctor: target lookup failed: %v\n", err)
			return 1
		}

		details, err = validateLaunchTargetWithLibrary(launchTarget, libPath)
		if err != nil {
			fmt.Fprintf(output, "doctor: launch target unsupported: %v\n", err)
			return 1
		}
	}

	fmt.Fprintf(output, "doctor: target=%s\n", resolvedTarget)
	if details != nil && details.UsedInterpreter {
		fmt.Fprintf(output, "doctor: script interpreter=%s\n", details.InterpreterPath)
	}
	if currentPlatformName() == "darwin" {
		reportDarwinLaunchTargetAdvisories(output, details)
	}
	if currentPlatformName() == "darwin" && details != nil && details.InjectionTargetPath != "" {
		if targetArchs, err := machOArchitectures(details.InjectionTargetPath); err == nil && len(targetArchs) > 0 {
			fmt.Fprintf(output, "doctor: target-arch=%s\n", strings.Join(targetArchs, ","))
		}
		if libraryArchs, err := machOArchitectures(libPath); err == nil && len(libraryArchs) > 0 {
			fmt.Fprintf(output, "doctor: library-arch=%s\n", strings.Join(libraryArchs, ","))
		}
	}

	if currentPlatformName() == "darwin" {
		if err := reportLaunchTargetSecurityInfo(output, resolvedTarget, ""); err != nil {
			fmt.Fprintf(output, "doctor: advisory: failed to inspect code signature metadata: %v\n", err)
		}
	}

	fmt.Fprintln(output, "doctor: launch target passed preflight")
	return 0
}

func reportDarwinLaunchTargetAdvisories(output io.Writer, details *launchTargetDetails) {
	if output == nil || details == nil {
		return
	}

	if strings.HasSuffix(details.RequestedPath, ".app") && details.ResolvedPath != "" {
		fmt.Fprintf(output, "doctor: app-bundle-resolved=%s\n", details.ResolvedPath)
	}

	injectionTarget := details.InjectionTargetPath
	if injectionTarget == "" {
		injectionTarget = details.ResolvedPath
	}
	if strings.Contains(injectionTarget, ".app/Contents/MacOS/") {
		fmt.Fprintln(output, "doctor: advisory: macOS GUI launches are experimental and only supported through the directly launched inner executable path")
		fmt.Fprintln(output, "doctor: advisory: if this app hands work off to an already-running session or external launcher, WrapGuard will not control the real process tree")
	}
}

func runSelfTest(ctx context.Context, ipcServer *IPCServer, socksServer *SOCKS5Server, execPath, libPath string, injectCfg injectionConfig, debug bool) int {
	if err := probeIPCReachability(ipcServer.SocketPath()); err != nil {
		logger.Errorf("Self-test failed: IPC socket is not reachable: %v", err)
		return 1
	}
	logger.Infof("Self-test check passed: IPC socket is reachable")

	if err := probeSOCKSReachability(socksServer.Port()); err != nil {
		logger.Errorf("Self-test failed: SOCKS listener is not reachable: %v", err)
		return 1
	}
	logger.Infof("Self-test check passed: SOCKS listener is reachable")

	subID, events := ipcServer.Subscribe()
	defer ipcServer.Unsubscribe(subID)

	cmd := exec.CommandContext(ctx, execPath, "--internal-self-test-probe="+selfTestProbeTarget)
	cmd.Env = buildChildEnv(os.Environ(), injectCfg, libPath, ipcServer.SocketPath(), socksServer.Port(), debug, false)
	cmd.SysProcAttr = childSysProcAttr()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		logger.Errorf("Self-test failed to start probe child: %v", err)
		return 1
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	readyMsg, err := waitForIPCMessage(events, done, 3*time.Second, "READY")
	if err != nil {
		logger.Errorf("Self-test failed: %v", err)
		_ = signalWrappedProcess(cmd, syscall.SIGKILL)
		return 1
	}
	logger.Infof("Self-test check passed: interceptor READY from pid %d", readyMsg.PID)

	connectMsg, err := waitForIPCMessage(events, done, 5*time.Second, "CONNECT")
	if err != nil {
		logger.Errorf("Self-test failed: %v", err)
		_ = signalWrappedProcess(cmd, syscall.SIGKILL)
		return 1
	}
	logger.Infof("Self-test check passed: intercepted outbound connect from pid %d to %s", connectMsg.PID, connectMsg.Addr)

	_ = signalWrappedProcess(cmd, syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = signalWrappedProcess(cmd, syscall.SIGKILL)
		<-done
	}

	logger.Infof("Self-test completed successfully")
	return 0
}

func runInternalSelfTestProbe(target string) int {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial("tcp", target)
	if err == nil {
		_ = conn.Close()
	}
	return 0
}
