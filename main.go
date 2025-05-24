package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

const version = "1.0.0"

func printUsage() {
	help := fmt.Sprintf(`
╦ ╦┬─┐┌─┐┌─┐╔═╗┬ ┬┌─┐┬─┐┌┬┐
║║║├┬┘├─┤├─┘║ ╦│ │├─┤├┬┘ ││
╚╩╝┴└─┴ ┴┴  ╚═╝└─┘┴ ┴┴└──┴┘ v%s

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
	flag.StringVar(&configPath, "config", "", "Path to WireGuard configuration file")
	flag.BoolVar(&showHelp, "help", false, "Show help message")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
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

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "\n\033[31m✗ Error:\033[0m No command specified\n")
		printUsage()
		os.Exit(1)
	}

	// Parse WireGuard configuration
	config, err := ParseWireGuardConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to parse WireGuard config: %v", err)
	}

	// Initialize the virtual network stack
	netStack, err := NewVirtualNetworkStack()
	if err != nil {
		log.Fatalf("Failed to create virtual network stack: %v", err)
	}

	// Initialize WireGuard with memory-based TUN
	wg, err := NewWireGuardProxy(config, netStack)
	if err != nil {
		log.Fatalf("Failed to initialize WireGuard: %v", err)
	}

	// Start the WireGuard proxy
	if err := wg.Start(); err != nil {
		log.Fatalf("Failed to start WireGuard: %v", err)
	}
	defer wg.Stop()

	// Start IPC server for LD_PRELOAD library communication
	ipcServer, err := NewIPCServer(netStack, wg)
	if err != nil {
		log.Fatalf("Failed to create IPC server: %v", err)
	}

	if err := ipcServer.Start(); err != nil {
		log.Fatalf("Failed to start IPC server: %v", err)
	}
	defer ipcServer.Stop()

	// Show startup message
	fmt.Printf("\n\033[32m✓\033[0m WrapGuard v%s initialized\n", version)
	fmt.Printf("\033[32m✓\033[0m Config: %s\n", configPath)
	fmt.Printf("\033[32m✓\033[0m Interface: %s\n", config.Interface.Address.String())
	fmt.Printf("\033[32m✓\033[0m Peer endpoint: %s\n", config.Peers[0].Endpoint.String())
	fmt.Printf("\033[32m✓\033[0m Launching: %s\n\n", strings.Join(args, " "))

	// Get path to our LD_PRELOAD library
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
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
		log.Fatalf("Failed to start child process: %v", err)
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
			log.Fatalf("Child process error: %v", err)
		}
	case sig := <-sigChan:
		// Forward signal to child process
		if cmd.Process != nil {
			cmd.Process.Signal(sig)
		}
		// Wait for child to exit
		<-done
	}
}
