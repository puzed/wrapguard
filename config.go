package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type WireGuardConfig struct {
	Interface InterfaceConfig
	Peers     []PeerConfig
}

type InterfaceConfig struct {
	PrivateKey string
	Address    *net.IPNet
	ListenPort int
	MTU        int
}

type PeerConfig struct {
	PublicKey           string
	Endpoint            *net.UDPAddr
	AllowedIPs          []*net.IPNet
	PersistentKeepalive int
	PresharedKey        string
}

func ParseWireGuardConfig(path string) (*WireGuardConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			MTU: 1420, // Default WireGuard MTU
		},
	}

	scanner := bufio.NewScanner(file)
	var currentSection string
	var currentPeer *PeerConfig

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			currentSection = section

			if section == "peer" {
				if currentPeer != nil {
					config.Peers = append(config.Peers, *currentPeer)
				}
				currentPeer = &PeerConfig{}
			}
			continue
		}

		// Parse key-value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch currentSection {
		case "interface":
			if err := parseInterfaceConfig(&config.Interface, key, value); err != nil {
				return nil, fmt.Errorf("invalid interface config: %w", err)
			}
		case "peer":
			if currentPeer == nil {
				currentPeer = &PeerConfig{}
			}
			if err := parsePeerConfig(currentPeer, key, value); err != nil {
				return nil, fmt.Errorf("invalid peer config: %w", err)
			}
		}
	}

	// Add the last peer if exists
	if currentPeer != nil {
		config.Peers = append(config.Peers, *currentPeer)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	// Validate configuration
	if config.Interface.PrivateKey == "" {
		return nil, fmt.Errorf("missing private key in interface section")
	}
	if config.Interface.Address == nil {
		return nil, fmt.Errorf("missing address in interface section")
	}
	if len(config.Peers) == 0 {
		return nil, fmt.Errorf("no peers configured")
	}

	return config, nil
}

func parseInterfaceConfig(config *InterfaceConfig, key, value string) error {
	switch key {
	case "privatekey":
		// Validate base64
		if _, err := base64.StdEncoding.DecodeString(value); err != nil {
			return fmt.Errorf("invalid private key: %w", err)
		}
		config.PrivateKey = value
	case "address":
		// Handle comma-separated addresses for dual-stack IPv4/IPv6
		addresses := strings.Split(value, ",")
		for _, addr := range addresses {
			addr = strings.TrimSpace(addr)
			ip, ipnet, err := net.ParseCIDR(addr)
			if err != nil {
				return fmt.Errorf("invalid address: %w", err)
			}
			ipnet.IP = ip
			// For now, use the first address as the primary
			if config.Address == nil {
				config.Address = ipnet
			}
		}
	case "listenport":
		port, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid listen port: %w", err)
		}
		config.ListenPort = port
	case "mtu":
		mtu, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid MTU: %w", err)
		}
		config.MTU = mtu
	}
	return nil
}

func parsePeerConfig(config *PeerConfig, key, value string) error {
	switch key {
	case "publickey":
		// Validate base64
		if _, err := base64.StdEncoding.DecodeString(value); err != nil {
			return fmt.Errorf("invalid public key: %w", err)
		}
		config.PublicKey = value
	case "endpoint":
		// Handle IPv6 endpoints with brackets
		addr, err := net.ResolveUDPAddr("udp", value)
		if err != nil {
			return fmt.Errorf("invalid endpoint: %w", err)
		}
		config.Endpoint = addr
	case "allowedips":
		ips := strings.Split(value, ",")
		for _, ipStr := range ips {
			ipStr = strings.TrimSpace(ipStr)
			_, ipnet, err := net.ParseCIDR(ipStr)
			if err != nil {
				// Try parsing as single IP
				ip := net.ParseIP(ipStr)
				if ip == nil {
					return fmt.Errorf("invalid allowed IP: %s", ipStr)
				}
				if ip.To4() != nil {
					ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
				} else {
					ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
				}
			}
			config.AllowedIPs = append(config.AllowedIPs, ipnet)
		}
	case "persistentkeepalive":
		keepalive, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid persistent keepalive: %w", err)
		}
		config.PersistentKeepalive = keepalive
	case "presharedkey":
		// Validate base64
		if _, err := base64.StdEncoding.DecodeString(value); err != nil {
			return fmt.Errorf("invalid preshared key: %w", err)
		}
		config.PresharedKey = value
	}
	return nil
}
