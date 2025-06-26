package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var version = "1.0.0-dev"

func printUsage() {
	help := fmt.Sprintf(`
╦ ╦┬─┐┌─┐┌─┐╔═╗┬ ┬┌─┐┬─┐┌┬┐
║║║├┬┘├─┤├─┘║ ╦│ │├─┤├┬┘ ││
╚╩╝┴└─┴ ┴┴  ╚═╝└─┘┴ ┴┴└──┴┘ %s

🔒 Userspace WireGuard proxy for transparent network tunneling

`, version)

	help += "\033[33mUSAGE:\033[0m\n"
	help += "    wrapguard --config=<path> -- <command> [args...]\n\n"

	help += "\033[33mEXAMPLES:\033[0m\n"
	help += "    \033[36m# Check your tunneled IP address\033[0m\n"
	help += "    wrapguard --config=wg0.conf -- curl https://icanhazip.com\n\n"

	help += "    \033[36m# Run a web server accessible through WireGuard\033[0m\n"
	help += "    wrapguard --config=wg0.conf -- python3 -m http.server 8080\n\n"

	help += "    \033[36m# Tunnel Node.js applications\033[0m\n"
	help += "    wrapguard --config=wg0.conf -- node app.js\n\n"

	help += "    \033[36m# Interactive shell with tunneled network\033[0m\n"
	help += "    wrapguard --config=wg0.conf -- bash\n\n"

	help += "\033[33mOPTIONS:\033[0m\n"
	help += "    --config=<path>    Path to WireGuard configuration file\n"
	help += "    --exit-node=<ip>   Route all traffic through specified peer IP\n"
	help += "    --route=<policy>   Add routing policy (CIDR:peerIP)\n"
	help += "    --log-level=<level> Set log level (error, warn, info, debug)\n"
	help += "    --log-file=<path>  Set file to write logs to (default: terminal)\n"
	help += "    --help             Show this help message\n"
	help += "    --version          Show version information\n\n"

	help += "\033[33mFEATURES:\033[0m\n"
	help += "    ✓ No root/sudo required\n"
	help += "    ✓ No kernel modules needed\n"
	help += "    ✓ Works in containers\n"
	help += "    ✓ Transparent to applications\n"
	help += "    ✓ Standard WireGuard configs\n\n"

	help += "\033[33mCONFIG EXAMPLE:\033[0m\n"
	help += "    [Interface]\n"
	help += "    PrivateKey = <your-private-key>\n"
	help += "    Address = 10.0.0.2/24\n\n"

	help += "    [Peer]\n"
	help += "    PublicKey = <server-public-key>\n"
	help += "    Endpoint = vpn.example.com:51820\n"
	help += "    AllowedIPs = 0.0.0.0/0\n\n"

	help += "\033[90mMore info: https://github.com/puzed/wrapguard\033[0m\n\n"

	os.Stderr.WriteString(help)
}

func main() {
	var configPath string
	var showHelp bool
	var showVersion bool
	var logLevelStr string
	var logFile string
	var exitNode string
	var routes []string
	flag.StringVar(&configPath, "config", "", "Path to WireGuard configuration file")
	flag.BoolVar(&showHelp, "help", false, "Show help message")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.StringVar(&logLevelStr, "log-level", "info", "Set log level (error, warn, info, debug)")
	flag.StringVar(&logFile, "log-file", "", "Set file to write logs to (default: terminal)")
	flag.StringVar(&exitNode, "exit-node", "", "Route all traffic through specified peer IP (e.g., 10.0.0.3)")
	flag.Func("route", "Add routing policy (format: CIDR:peerIP, e.g., 192.168.1.0/24:10.0.0.3)", func(value string) error {
		routes = append(routes, value)
		return nil
	})
	flag.Usage = printUsage
	flag.Parse()

	if showVersion {
		fmt.Printf("wrapguard version %s\n", version)
		os.Exit(0)
	}

	if showHelp {
		printUsage()
		os.Exit(0)
	}

	if configPath == "" {
		printUsage()
		os.Exit(1)
	}

	// Parse log level
	logLevel, err := ParseLogLevel(logLevelStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n\033[31m✗ Error:\033[0m Invalid log level: %v\n", err)
		os.Exit(1)
	}

	// Setup logger output
	var logOutput io.Writer = os.Stderr
	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n\033[31m✗ Error:\033[0m Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		logOutput = file
	}

	// Create logger
	logger := NewLogger(logLevel, logOutput)
	SetGlobalLogger(logger)

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "\n\033[31m✗ Error:\033[0m No command specified\n")
		printUsage()
		os.Exit(1)
	}

	// Parse WireGuard configuration
	config, err := ParseConfig(configPath)
	if err != nil {
		logger.Errorf("Failed to parse WireGuard config: %v", err)
		os.Exit(1)
	}

	// Apply CLI routing options
	if exitNode != "" || len(routes) > 0 {
		if err := ApplyCLIRoutes(config, exitNode, routes); err != nil {
			logger.Errorf("Failed to apply routing options: %v", err)
			os.Exit(1)
		}
	}

	// Create IPC server for communication with LD_PRELOAD library
	ipcServer, err := NewIPCServer()
	if err != nil {
		logger.Errorf("Failed to start IPC server: %v", err)
		os.Exit(1)
	}
	defer ipcServer.Close()

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start WireGuard tunnel
	logger.Infof("Creating WireGuard tunnel...")
	tunnel, err := NewTunnel(ctx, config)
	if err != nil {
		logger.Errorf("Failed to create tunnel: %v", err)
		os.Exit(1)
	}
	defer tunnel.Close()
	logger.Infof("WireGuard tunnel created successfully")

	// Start SOCKS5 server that routes through WireGuard tunnel
	logger.Infof("Starting SOCKS5 server...")
	socksServer, err := NewSOCKS5Server(tunnel)
	if err != nil {
		logger.Errorf("Failed to start SOCKS5 server: %v", err)
		os.Exit(1)
	}
	defer socksServer.Close()
	logger.Infof("SOCKS5 server started on port %d", socksServer.Port())

	// Start port forwarder for incoming connections
	forwarder := NewPortForwarder(tunnel, ipcServer.MessageChan())
	go forwarder.Run(ctx)

	// Show startup messages using structured logging
	logger.Infof("WrapGuard v%s initialized", version)
	logger.Infof("Config: %s", configPath)
	logger.Infof("Interface: %s", config.Interface.Address)
	if len(config.Peers) > 0 {
		logger.Infof("Peer endpoint: %s", config.Peers[0].Endpoint)
	}
	logger.Infof("Launching: [%s]", strings.Join(args, " "))

	// Get path to our LD_PRELOAD library
	execPath, err := os.Executable()
	if err != nil {
		logger.Errorf("Failed to get executable path: %v", err)
		os.Exit(1)
	}
	libPath := filepath.Join(filepath.Dir(execPath), "libwrapguard.so")

	// Prepare child process
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set LD_PRELOAD and IPC socket path
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("LD_PRELOAD=%s", libPath),
		fmt.Sprintf("WRAPGUARD_IPC_PATH=%s", ipcServer.SocketPath()),
		fmt.Sprintf("WRAPGUARD_SOCKS_PORT=%d", socksServer.Port()),
	)

	// Start the child process
	if err := cmd.Start(); err != nil {
		logger.Errorf("Failed to start child process: %v", err)
		os.Exit(1)
	}

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for child process or signal
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			logger.Errorf("Child process error: %v", err)
			os.Exit(1)
		}
		// Exit cleanly when child process completes successfully
		os.Exit(0)
	case sig := <-sigChan:
		logger.Infof("Received signal %v, shutting down...", sig)
		// Forward signal to child process
		if cmd.Process != nil {
			cmd.Process.Signal(sig)
		}
		// Wait for child to exit
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			logger.Warnf("Child process did not exit gracefully, killing...")
			cmd.Process.Kill()
		}
		os.Exit(1)
	}
}
