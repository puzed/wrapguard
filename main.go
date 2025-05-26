package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func printUsage() {
	help := fmt.Sprintf(`
╦ ╦┬─┐┌─┐┌─┐╔═╗┬ ┬┌─┐┬─┐┌┬┐
║║║├┬┘├─┤├─┘║ ╦│ │├─┤├┬┘ ││
╚╩╝┴└─┴ ┴┴  ╚═╝└─┘┴ ┴┴└──┴┘ %s

🔒 Userspace WireGuard proxy for transparent network tunneling

`, Version)

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
	flag.StringVar(&configPath, "config", "", "Path to WireGuard configuration file")
	flag.BoolVar(&showHelp, "help", false, "Show help message")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.StringVar(&logLevelStr, "log-level", "info", "Set log level (error, warn, info, debug)")
	flag.StringVar(&logFile, "log-file", "", "Set file to write logs to (default: terminal)")
	flag.Usage = printUsage
	flag.Parse()

	if showVersion {
		fmt.Printf("wrapguard version %s\n", Version)
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
	var logOutput io.Writer = os.Stdout
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

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "\n\033[31m✗ Error:\033[0m No command specified\n")
		printUsage()
		os.Exit(1)
	}

	// Parse WireGuard configuration
	config, err := ParseWireGuardConfig(configPath)
	if err != nil {
		logger.Errorf("Failed to parse WireGuard config: %v", err)
		os.Exit(1)
	}

	// Initialize the virtual network stack
	netStack, err := NewVirtualNetworkStack()
	if err != nil {
		logger.Errorf("Failed to create virtual network stack: %v", err)
		os.Exit(1)
	}

	// Initialize WireGuard with memory-based TUN
	wg, err := NewWireGuardProxy(config, netStack, logger)
	if err != nil {
		logger.Errorf("Failed to initialize WireGuard: %v", err)
		os.Exit(1)
	}

	// Start the WireGuard proxy
	if err := wg.Start(); err != nil {
		logger.Errorf("Failed to start WireGuard: %v", err)
		os.Exit(1)
	}
	defer wg.Stop()

	// Start IPC server for LD_PRELOAD library communication
	ipcServer, err := NewIPCServer(netStack, wg)
	if err != nil {
		logger.Errorf("Failed to create IPC server: %v", err)
		os.Exit(1)
	}

	if err := ipcServer.Start(); err != nil {
		logger.Errorf("Failed to start IPC server: %v", err)
		os.Exit(1)
	}
	defer ipcServer.Stop()

	// Show startup messages using structured logging
	logger.Infof("WrapGuard %s initialized", Version)
	logger.Infof("Config: %s", configPath)
	logger.Infof("Interface: %s", config.Interface.Address.String())
	logger.Infof("Peer endpoint: %s", config.Peers[0].Endpoint.String())
	logger.Infof("Launching: %s", strings.Join(args, " "))

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
		// Forward signal to child process
		if cmd.Process != nil {
			cmd.Process.Signal(sig)
		}
		// Wait for child to exit
		<-done
		os.Exit(1)
	}
}
