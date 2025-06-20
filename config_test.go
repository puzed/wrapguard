package main

import (
	"encoding/base64"
	"net/netip"
	"os"
	"testing"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		expectError bool
		validate    func(*WireGuardConfig) error
	}{
		{
			name: "valid basic config",
			config: `[Interface]
PrivateKey = ` + generateTestKey() + `
Address = 10.0.0.2/24

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820
AllowedIPs = 0.0.0.0/0`,
			expectError: false,
			validate: func(c *WireGuardConfig) error {
				if c.Interface.Address != "10.0.0.2/24" {
					t.Errorf("expected address 10.0.0.2/24, got %s", c.Interface.Address)
				}
				if len(c.Peers) != 1 {
					t.Errorf("expected 1 peer, got %d", len(c.Peers))
				}
				if c.Peers[0].Endpoint != "192.168.1.1:51820" {
					t.Errorf("expected endpoint 192.168.1.1:51820, got %s", c.Peers[0].Endpoint)
				}
				return nil
			},
		},
		{
			name: "config with DNS",
			config: `[Interface]
PrivateKey = ` + generateTestKey() + `
Address = 10.0.0.2/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0`,
			expectError: false,
			validate: func(c *WireGuardConfig) error {
				if len(c.Interface.DNS) != 2 {
					t.Errorf("expected 2 DNS servers, got %d", len(c.Interface.DNS))
				}
				if c.Interface.DNS[0] != "1.1.1.1" || c.Interface.DNS[1] != "8.8.8.8" {
					t.Errorf("unexpected DNS servers: %v", c.Interface.DNS)
				}
				return nil
			},
		},
		{
			name: "config with listen port",
			config: `[Interface]
PrivateKey = ` + generateTestKey() + `
Address = 10.0.0.2/24
ListenPort = 51820

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820
AllowedIPs = 0.0.0.0/0`,
			expectError: false,
			validate: func(c *WireGuardConfig) error {
				if c.Interface.ListenPort != 51820 {
					t.Errorf("expected listen port 51820, got %d", c.Interface.ListenPort)
				}
				return nil
			},
		},
		{
			name: "config with preshared key",
			config: `[Interface]
PrivateKey = ` + generateTestKey() + `
Address = 10.0.0.2/24

[Peer]
PublicKey = ` + generateTestKey() + `
PresharedKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820
AllowedIPs = 0.0.0.0/0`,
			expectError: false,
			validate: func(c *WireGuardConfig) error {
				if c.Peers[0].PresharedKey == "" {
					t.Error("expected preshared key to be set")
				}
				return nil
			},
		},
		{
			name: "config with keepalive",
			config: `[Interface]
PrivateKey = ` + generateTestKey() + `
Address = 10.0.0.2/24

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25`,
			expectError: false,
			validate: func(c *WireGuardConfig) error {
				if c.Peers[0].PersistentKeepalive != 25 {
					t.Errorf("expected keepalive 25, got %d", c.Peers[0].PersistentKeepalive)
				}
				return nil
			},
		},
		{
			name: "config with multiple peers",
			config: `[Interface]
PrivateKey = ` + generateTestKey() + `
Address = 10.0.0.2/24

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820
AllowedIPs = 10.0.0.0/24

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.2:51820
AllowedIPs = 10.1.0.0/24`,
			expectError: false,
			validate: func(c *WireGuardConfig) error {
				if len(c.Peers) != 2 {
					t.Errorf("expected 2 peers, got %d", len(c.Peers))
				}
				return nil
			},
		},
		{
			name: "config with comments and empty lines",
			config: `# This is a comment
[Interface]
# Interface configuration
PrivateKey = ` + generateTestKey() + `
Address = 10.0.0.2/24

# Peer configuration
[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820
AllowedIPs = 0.0.0.0/0
# End of config`,
			expectError: false,
			validate: func(c *WireGuardConfig) error {
				if c.Interface.Address != "10.0.0.2/24" {
					t.Errorf("expected address 10.0.0.2/24, got %s", c.Interface.Address)
				}
				return nil
			},
		},
		{
			name: "missing private key",
			config: `[Interface]
Address = 10.0.0.2/24

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820
AllowedIPs = 0.0.0.0/0`,
			expectError: true,
		},
		{
			name: "missing address",
			config: `[Interface]
PrivateKey = ` + generateTestKey() + `

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820
AllowedIPs = 0.0.0.0/0`,
			expectError: true,
		},
		{
			name: "missing peer",
			config: `[Interface]
PrivateKey = ` + generateTestKey() + `
Address = 10.0.0.2/24`,
			expectError: true,
		},
		{
			name: "missing peer public key",
			config: `[Interface]
PrivateKey = ` + generateTestKey() + `
Address = 10.0.0.2/24

[Peer]
Endpoint = 192.168.1.1:51820
AllowedIPs = 0.0.0.0/0`,
			expectError: true,
		},
		{
			name: "missing peer allowed IPs",
			config: `[Interface]
PrivateKey = ` + generateTestKey() + `
Address = 10.0.0.2/24

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820`,
			expectError: true,
		},
		{
			name: "invalid private key",
			config: `[Interface]
PrivateKey = invalid-key
Address = 10.0.0.2/24

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820
AllowedIPs = 0.0.0.0/0`,
			expectError: true,
		},
		{
			name: "invalid address format",
			config: `[Interface]
PrivateKey = ` + generateTestKey() + `
Address = invalid-address

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820
AllowedIPs = 0.0.0.0/0`,
			expectError: true,
		},
		{
			name: "invalid allowed IP format",
			config: `[Interface]
PrivateKey = ` + generateTestKey() + `
Address = 10.0.0.2/24

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820
AllowedIPs = invalid-ip`,
			expectError: true,
		},
		{
			name: "invalid listen port",
			config: `[Interface]
PrivateKey = ` + generateTestKey() + `
Address = 10.0.0.2/24
ListenPort = invalid-port

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820
AllowedIPs = 0.0.0.0/0`,
			expectError: true,
		},
		{
			name: "invalid keepalive",
			config: `[Interface]
PrivateKey = ` + generateTestKey() + `
Address = 10.0.0.2/24

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = invalid-keepalive`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tempFile, err := os.CreateTemp("", "wg-test-*.conf")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tempFile.Name())

			if _, err := tempFile.WriteString(tt.config); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}
			tempFile.Close()

			// Parse config
			config, err := ParseConfig(tempFile.Name())

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if config == nil {
				t.Error("config is nil")
				return
			}

			// Run validation if provided
			if tt.validate != nil {
				if err := tt.validate(config); err != nil {
					t.Errorf("validation failed: %v", err)
				}
			}
		})
	}
}

func TestParseConfigFileNotFound(t *testing.T) {
	_, err := ParseConfig("/nonexistent/file.conf")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestGetInterfaceIP(t *testing.T) {
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			Address: "10.0.0.2/24",
		},
	}

	ip, err := config.GetInterfaceIP()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	expected, _ := netip.ParseAddr("10.0.0.2")
	if ip != expected {
		t.Errorf("expected IP %v, got %v", expected, ip)
	}
}

func TestGetInterfaceIPInvalid(t *testing.T) {
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			Address: "invalid-address",
		},
	}

	_, err := config.GetInterfaceIP()
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestGetInterfacePrefix(t *testing.T) {
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			Address: "10.0.0.2/24",
		},
	}

	prefix, err := config.GetInterfacePrefix()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	expected, _ := netip.ParsePrefix("10.0.0.2/24")
	if prefix != expected {
		t.Errorf("expected prefix %v, got %v", expected, prefix)
	}
}

func TestBase64ToHex(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		expectedLen int
	}{
		{
			name:        "valid key",
			input:       generateTestKey(),
			expectError: false,
			expectedLen: 64, // 32 bytes = 64 hex chars
		},
		{
			name:        "invalid base64",
			input:       "invalid-base64!@#",
			expectError: true,
		},
		{
			name:        "wrong length",
			input:       base64.StdEncoding.EncodeToString([]byte("short")),
			expectError: true,
		},
		{
			name:        "empty key",
			input:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := base64ToHex(tt.input)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(result) != tt.expectedLen {
				t.Errorf("expected length %d, got %d", tt.expectedLen, len(result))
			}
		})
	}
}

func TestResolveEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		expectError bool
	}{
		{
			name:        "IP endpoint",
			endpoint:    "192.168.1.1:51820",
			expectError: false,
		},
		{
			name:        "localhost endpoint",
			endpoint:    "localhost:51820",
			expectError: false,
		},
		{
			name:        "invalid format",
			endpoint:    "invalid-endpoint",
			expectError: true,
		},
		{
			name:        "nonexistent hostname",
			endpoint:    "nonexistent-hostname-12345.invalid:51820",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resolveEndpoint(tt.endpoint)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result == "" {
				t.Error("expected non-empty result")
			}
		})
	}
}

func TestParseInterfaceField(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		value       string
		expectError bool
		validate    func(*InterfaceConfig) error
	}{
		{
			name:        "private key",
			key:         "PrivateKey",
			value:       generateTestKey(),
			expectError: false,
			validate: func(iface *InterfaceConfig) error {
				if iface.PrivateKey == "" {
					t.Error("private key not set")
				}
				return nil
			},
		},
		{
			name:        "address",
			key:         "Address",
			value:       "10.0.0.2/24",
			expectError: false,
			validate: func(iface *InterfaceConfig) error {
				if iface.Address != "10.0.0.2/24" {
					t.Errorf("expected address 10.0.0.2/24, got %s", iface.Address)
				}
				return nil
			},
		},
		{
			name:        "DNS",
			key:         "DNS",
			value:       "1.1.1.1, 8.8.8.8",
			expectError: false,
			validate: func(iface *InterfaceConfig) error {
				if len(iface.DNS) != 2 {
					t.Errorf("expected 2 DNS servers, got %d", len(iface.DNS))
				}
				return nil
			},
		},
		{
			name:        "listen port",
			key:         "ListenPort",
			value:       "51820",
			expectError: false,
			validate: func(iface *InterfaceConfig) error {
				if iface.ListenPort != 51820 {
					t.Errorf("expected listen port 51820, got %d", iface.ListenPort)
				}
				return nil
			},
		},
		{
			name:        "invalid private key",
			key:         "PrivateKey",
			value:       "invalid-key",
			expectError: true,
		},
		{
			name:        "invalid listen port",
			key:         "ListenPort",
			value:       "invalid-port",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface := &InterfaceConfig{}
			err := parseInterfaceField(iface, tt.key, tt.value)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.validate != nil {
				if err := tt.validate(iface); err != nil {
					t.Errorf("validation failed: %v", err)
				}
			}
		})
	}
}

func TestParsePeerField(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		value       string
		expectError bool
		validate    func(*PeerConfig) error
	}{
		{
			name:        "public key",
			key:         "PublicKey",
			value:       generateTestKey(),
			expectError: false,
			validate: func(peer *PeerConfig) error {
				if peer.PublicKey == "" {
					t.Error("public key not set")
				}
				return nil
			},
		},
		{
			name:        "preshared key",
			key:         "PresharedKey",
			value:       generateTestKey(),
			expectError: false,
			validate: func(peer *PeerConfig) error {
				if peer.PresharedKey == "" {
					t.Error("preshared key not set")
				}
				return nil
			},
		},
		{
			name:        "endpoint",
			key:         "Endpoint",
			value:       "192.168.1.1:51820",
			expectError: false,
			validate: func(peer *PeerConfig) error {
				if peer.Endpoint != "192.168.1.1:51820" {
					t.Errorf("expected endpoint 192.168.1.1:51820, got %s", peer.Endpoint)
				}
				return nil
			},
		},
		{
			name:        "allowed IPs",
			key:         "AllowedIPs",
			value:       "0.0.0.0/0, 10.0.0.0/24",
			expectError: false,
			validate: func(peer *PeerConfig) error {
				if len(peer.AllowedIPs) != 2 {
					t.Errorf("expected 2 allowed IPs, got %d", len(peer.AllowedIPs))
				}
				return nil
			},
		},
		{
			name:        "persistent keepalive",
			key:         "PersistentKeepalive",
			value:       "25",
			expectError: false,
			validate: func(peer *PeerConfig) error {
				if peer.PersistentKeepalive != 25 {
					t.Errorf("expected keepalive 25, got %d", peer.PersistentKeepalive)
				}
				return nil
			},
		},
		{
			name:        "invalid public key",
			key:         "PublicKey",
			value:       "invalid-key",
			expectError: true,
		},
		{
			name:        "invalid endpoint",
			key:         "Endpoint",
			value:       "invalid-endpoint",
			expectError: true,
		},
		{
			name:        "invalid keepalive",
			key:         "PersistentKeepalive",
			value:       "invalid-keepalive",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer := &PeerConfig{}
			err := parsePeerField(peer, tt.key, tt.value)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.validate != nil {
				if err := tt.validate(peer); err != nil {
					t.Errorf("validation failed: %v", err)
				}
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *WireGuardConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: &WireGuardConfig{
				Interface: InterfaceConfig{
					PrivateKey: "test-key",
					Address:    "10.0.0.2/24",
				},
				Peers: []PeerConfig{
					{
						PublicKey:  "test-public-key",
						AllowedIPs: []string{"0.0.0.0/0"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "missing private key",
			config: &WireGuardConfig{
				Interface: InterfaceConfig{
					Address: "10.0.0.2/24",
				},
				Peers: []PeerConfig{
					{
						PublicKey:  "test-public-key",
						AllowedIPs: []string{"0.0.0.0/0"},
					},
				},
			},
			expectError: true,
		},
		{
			name: "missing address",
			config: &WireGuardConfig{
				Interface: InterfaceConfig{
					PrivateKey: "test-key",
				},
				Peers: []PeerConfig{
					{
						PublicKey:  "test-public-key",
						AllowedIPs: []string{"0.0.0.0/0"},
					},
				},
			},
			expectError: true,
		},
		{
			name: "invalid address format",
			config: &WireGuardConfig{
				Interface: InterfaceConfig{
					PrivateKey: "test-key",
					Address:    "invalid-address",
				},
				Peers: []PeerConfig{
					{
						PublicKey:  "test-public-key",
						AllowedIPs: []string{"0.0.0.0/0"},
					},
				},
			},
			expectError: true,
		},
		{
			name: "no peers",
			config: &WireGuardConfig{
				Interface: InterfaceConfig{
					PrivateKey: "test-key",
					Address:    "10.0.0.2/24",
				},
				Peers: []PeerConfig{},
			},
			expectError: true,
		},
		{
			name: "peer missing public key",
			config: &WireGuardConfig{
				Interface: InterfaceConfig{
					PrivateKey: "test-key",
					Address:    "10.0.0.2/24",
				},
				Peers: []PeerConfig{
					{
						AllowedIPs: []string{"0.0.0.0/0"},
					},
				},
			},
			expectError: true,
		},
		{
			name: "peer missing allowed IPs",
			config: &WireGuardConfig{
				Interface: InterfaceConfig{
					PrivateKey: "test-key",
					Address:    "10.0.0.2/24",
				},
				Peers: []PeerConfig{
					{
						PublicKey: "test-public-key",
					},
				},
			},
			expectError: true,
		},
		{
			name: "peer invalid allowed IP",
			config: &WireGuardConfig{
				Interface: InterfaceConfig{
					PrivateKey: "test-key",
					Address:    "10.0.0.2/24",
				},
				Peers: []PeerConfig{
					{
						PublicKey:  "test-public-key",
						AllowedIPs: []string{"invalid-ip"},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Helper function to generate a test WireGuard key
func generateTestKey() string {
	// Generate 32 random bytes and encode as base64
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// Benchmark tests for performance
func BenchmarkParseConfig(b *testing.B) {
	config := `[Interface]
PrivateKey = ` + generateTestKey() + `
Address = 10.0.0.2/24

[Peer]
PublicKey = ` + generateTestKey() + `
Endpoint = 192.168.1.1:51820
AllowedIPs = 0.0.0.0/0`

	tempFile, err := os.CreateTemp("", "wg-bench-*.conf")
	if err != nil {
		b.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.WriteString(config); err != nil {
		b.Fatalf("failed to write config: %v", err)
	}
	tempFile.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseConfig(tempFile.Name())
		if err != nil {
			b.Fatalf("parse error: %v", err)
		}
	}
}

func BenchmarkBase64ToHex(b *testing.B) {
	key := generateTestKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := base64ToHex(key)
		if err != nil {
			b.Fatalf("conversion error: %v", err)
		}
	}
}
