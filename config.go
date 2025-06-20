package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type InterfaceConfig struct {
	PrivateKey string
	Address    string
	DNS        []string
	ListenPort int
}

type PeerConfig struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepalive int
}

type WireGuardConfig struct {
	Interface InterfaceConfig
	Peers     []PeerConfig
}

func ParseConfig(filename string) (*WireGuardConfig, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	config := &WireGuardConfig{}
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
			currentSection = strings.ToLower(line[1 : len(line)-1])
			if currentSection == "peer" {
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

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch currentSection {
		case "interface":
			if err := parseInterfaceField(&config.Interface, key, value); err != nil {
				return nil, fmt.Errorf("error parsing interface field %s: %w", key, err)
			}
		case "peer":
			if currentPeer != nil {
				if err := parsePeerField(currentPeer, key, value); err != nil {
					return nil, fmt.Errorf("error parsing peer field %s: %w", key, err)
				}
			}
		}
	}

	// Add the last peer if exists
	if currentPeer != nil {
		config.Peers = append(config.Peers, *currentPeer)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return config, nil
}

func parseInterfaceField(iface *InterfaceConfig, key, value string) error {
	switch strings.ToLower(key) {
	case "privatekey":
		// Convert base64 private key to hex for wireguard-go IPC
		hexKey, err := base64ToHex(value)
		if err != nil {
			return fmt.Errorf("invalid private key format: %w", err)
		}
		iface.PrivateKey = hexKey
	case "address":
		iface.Address = value
	case "dns":
		// Parse comma-separated DNS servers
		dns := strings.Split(value, ",")
		for i, d := range dns {
			dns[i] = strings.TrimSpace(d)
		}
		iface.DNS = dns
	case "listenport":
		port, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid listen port: %w", err)
		}
		iface.ListenPort = port
	}
	return nil
}

func parsePeerField(peer *PeerConfig, key, value string) error {
	switch strings.ToLower(key) {
	case "publickey":
		// Convert base64 public key to hex for wireguard-go IPC
		hexKey, err := base64ToHex(value)
		if err != nil {
			return fmt.Errorf("invalid public key format: %w", err)
		}
		peer.PublicKey = hexKey
	case "presharedkey":
		// Convert base64 preshared key to hex for wireguard-go IPC
		hexKey, err := base64ToHex(value)
		if err != nil {
			return fmt.Errorf("invalid preshared key format: %w", err)
		}
		peer.PresharedKey = hexKey
	case "endpoint":
		// Resolve hostname in endpoint to IP address
		resolvedEndpoint, err := resolveEndpoint(value)
		if err != nil {
			return fmt.Errorf("failed to resolve endpoint %s: %w", value, err)
		}
		peer.Endpoint = resolvedEndpoint
	case "allowedips":
		// Parse comma-separated allowed IPs
		ips := strings.Split(value, ",")
		for i, ip := range ips {
			ips[i] = strings.TrimSpace(ip)
		}
		peer.AllowedIPs = ips
	case "persistentkeepalive":
		keepalive, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid persistent keepalive: %w", err)
		}
		peer.PersistentKeepalive = keepalive
	}
	return nil
}

func validateConfig(config *WireGuardConfig) error {
	// Validate interface
	if config.Interface.PrivateKey == "" {
		return fmt.Errorf("interface private key is required")
	}

	if config.Interface.Address == "" {
		return fmt.Errorf("interface address is required")
	}

	// Validate address format
	if _, err := netip.ParsePrefix(config.Interface.Address); err != nil {
		return fmt.Errorf("invalid interface address format: %w", err)
	}

	// Validate at least one peer
	if len(config.Peers) == 0 {
		return fmt.Errorf("at least one peer is required")
	}

	// Validate peers
	for i, peer := range config.Peers {
		if peer.PublicKey == "" {
			return fmt.Errorf("peer %d: public key is required", i)
		}

		if len(peer.AllowedIPs) == 0 {
			return fmt.Errorf("peer %d: at least one allowed IP is required", i)
		}

		// Validate allowed IPs format
		for _, allowedIP := range peer.AllowedIPs {
			if _, err := netip.ParsePrefix(allowedIP); err != nil {
				return fmt.Errorf("peer %d: invalid allowed IP format %s: %w", i, allowedIP, err)
			}
		}
	}

	return nil
}

// GetInterfaceIP extracts the IP address from the interface address (without CIDR)
func (c *WireGuardConfig) GetInterfaceIP() (netip.Addr, error) {
	prefix, err := netip.ParsePrefix(c.Interface.Address)
	if err != nil {
		return netip.Addr{}, err
	}
	return prefix.Addr(), nil
}

// GetInterfacePrefix returns the interface address as a prefix
func (c *WireGuardConfig) GetInterfacePrefix() (netip.Prefix, error) {
	return netip.ParsePrefix(c.Interface.Address)
}

// base64ToHex converts a base64-encoded WireGuard key to lowercase hex format
// required by wireguard-go IPC protocol
func base64ToHex(base64Key string) (string, error) {
	// Decode base64 key
	keyBytes, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 key: %w", err)
	}

	// WireGuard keys should be exactly 32 bytes
	if len(keyBytes) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(keyBytes))
	}

	// Convert to lowercase hex
	return hex.EncodeToString(keyBytes), nil
}

// resolveEndpoint resolves a hostname:port endpoint to IP:port format
// required by wireguard-go which expects IP addresses, not hostnames
func resolveEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint format: %w", err)
	}

	// Check if host is already an IP address
	if ip := net.ParseIP(host); ip != nil {
		return endpoint, nil // Already an IP, return as-is
	}

	// Resolve hostname to IP
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve hostname %s: %w", host, err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for hostname %s", host)
	}

	// Use the first IP address (prefer IPv4)
	var resolvedIP net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			resolvedIP = ip
			break
		}
	}

	// If no IPv4 found, use the first IP
	if resolvedIP == nil {
		resolvedIP = ips[0]
	}

	return net.JoinHostPort(resolvedIP.String(), port), nil
}
