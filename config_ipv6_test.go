package main

import (
	"net"
	"os"
	"testing"
)

func TestParseWireGuardConfigIPv6(t *testing.T) {
	// Create a temporary config file with IPv6 addresses
	content := `[Interface]
PrivateKey = MFUi5Ifm+AoCB83PFlv4MIbT+gUUOCATAR1o+qJnuVc=
Address = 2001:db8::1/64
ListenPort = 51820
MTU = 1420

[Peer]
PublicKey = lBKGHDRS3JrAJCFHJLe4cqhMnaaymBpKAhTxOFb8gT8=
AllowedIPs = ::/0
Endpoint = [2001:db8::2]:51820
PersistentKeepalive = 25
`

	tmpFile, err := os.CreateTemp("", "test-wg-ipv6-*.conf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	config, err := ParseWireGuardConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// Check interface configuration
	expectedIP := net.ParseIP("2001:db8::1")
	if !config.Interface.Address.IP.Equal(expectedIP) {
		t.Errorf("Expected interface IP %v, got %v", expectedIP, config.Interface.Address.IP)
	}

	expectedMask := net.CIDRMask(64, 128)
	if config.Interface.Address.Mask.String() != expectedMask.String() {
		t.Errorf("Expected mask %v, got %v", expectedMask, config.Interface.Address.Mask)
	}

	if config.Interface.ListenPort != 51820 {
		t.Errorf("Expected listen port 51820, got %d", config.Interface.ListenPort)
	}

	// Check peer configuration
	if len(config.Peers) != 1 {
		t.Fatalf("Expected 1 peer, got %d", len(config.Peers))
	}

	peer := config.Peers[0]
	if peer.PublicKey != "lBKGHDRS3JrAJCFHJLe4cqhMnaaymBpKAhTxOFb8gT8=" {
		t.Errorf("Unexpected public key: %s", peer.PublicKey)
	}

	expectedEndpoint := &net.UDPAddr{
		IP:   net.ParseIP("2001:db8::2"),
		Port: 51820,
	}
	if peer.Endpoint.String() != expectedEndpoint.String() {
		t.Errorf("Expected endpoint %v, got %v", expectedEndpoint, peer.Endpoint)
	}

	// Check allowed IPs
	if len(peer.AllowedIPs) != 1 {
		t.Fatalf("Expected 1 allowed IP, got %d", len(peer.AllowedIPs))
	}

	expectedAllowedIP := &net.IPNet{
		IP:   net.IPv6zero,
		Mask: net.CIDRMask(0, 128),
	}
	if peer.AllowedIPs[0].String() != expectedAllowedIP.String() {
		t.Errorf("Expected allowed IP %v, got %v", expectedAllowedIP, peer.AllowedIPs[0])
	}
}

func TestParseWireGuardConfigDualStack(t *testing.T) {
	// Create a temporary config file with both IPv4 and IPv6 addresses
	content := `[Interface]
PrivateKey = MFUi5Ifm+AoCB83PFlv4MIbT+gUUOCATAR1o+qJnuVc=
Address = 10.2.0.2/32, 2001:db8::1/64
ListenPort = 51820

[Peer]
PublicKey = lBKGHDRS3JrAJCFHJLe4cqhMnaaymBpKAhTxOFb8gT8=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 192.168.64.6:51820
PersistentKeepalive = 25
`

	tmpFile, err := os.CreateTemp("", "test-wg-dual-*.conf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	config, err := ParseWireGuardConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// Check interface configuration (should use the first address)
	expectedIP := net.ParseIP("10.2.0.2")
	if !config.Interface.Address.IP.Equal(expectedIP) {
		t.Errorf("Expected interface IP %v, got %v", expectedIP, config.Interface.Address.IP)
	}

	// Check peer configuration
	if len(config.Peers) != 1 {
		t.Fatalf("Expected 1 peer, got %d", len(config.Peers))
	}

	peer := config.Peers[0]

	// Check allowed IPs (should have both IPv4 and IPv6)
	if len(peer.AllowedIPs) != 2 {
		t.Fatalf("Expected 2 allowed IPs, got %d", len(peer.AllowedIPs))
	}

	// Check IPv4 allowed IP
	expectedIPv4 := &net.IPNet{
		IP:   net.IPv4zero,
		Mask: net.CIDRMask(0, 32),
	}
	found := false
	for _, allowedIP := range peer.AllowedIPs {
		if allowedIP.String() == expectedIPv4.String() {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected IPv4 allowed IP %v not found", expectedIPv4)
	}

	// Check IPv6 allowed IP
	expectedIPv6 := &net.IPNet{
		IP:   net.IPv6zero,
		Mask: net.CIDRMask(0, 128),
	}
	found = false
	for _, allowedIP := range peer.AllowedIPs {
		if allowedIP.String() == expectedIPv6.String() {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected IPv6 allowed IP %v not found", expectedIPv6)
	}
}

func TestParseIPv6EndpointFormats(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		expected string
	}{
		{
			name:     "IPv6 with brackets",
			endpoint: "[2001:db8::1]:51820",
			expected: "[2001:db8::1]:51820",
		},
		{
			name:     "IPv4 endpoint",
			endpoint: "192.168.1.1:51820",
			expected: "192.168.1.1:51820",
		},
		{
			name:     "IPv6 localhost with brackets",
			endpoint: "[::1]:51820",
			expected: "[::1]:51820",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := `[Interface]
PrivateKey = MFUi5Ifm+AoCB83PFlv4MIbT+gUUOCATAR1o+qJnuVc=
Address = 10.2.0.2/32

[Peer]
PublicKey = lBKGHDRS3JrAJCFHJLe4cqhMnaaymBpKAhTxOFb8gT8=
AllowedIPs = 0.0.0.0/0
Endpoint = ` + tt.endpoint + `
`

			tmpFile, err := os.CreateTemp("", "test-wg-endpoint-*.conf")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.WriteString(content); err != nil {
				t.Fatalf("Failed to write temp file: %v", err)
			}
			tmpFile.Close()

			config, err := ParseWireGuardConfig(tmpFile.Name())
			if err != nil {
				t.Fatalf("Failed to parse config: %v", err)
			}

			if len(config.Peers) != 1 {
				t.Fatalf("Expected 1 peer, got %d", len(config.Peers))
			}

			peer := config.Peers[0]
			if peer.Endpoint.String() != tt.expected {
				t.Errorf("Expected endpoint %s, got %s", tt.expected, peer.Endpoint.String())
			}
		})
	}
}
