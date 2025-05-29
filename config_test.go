package main

import (
	"os"
	"testing"
)

func TestParseWireGuardConfig(t *testing.T) {
	// Create a temporary config file
	configContent := `[Interface]
PrivateKey = YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==
Address = 10.0.0.2/24
ListenPort = 51820
MTU = 1420

[Peer]
PublicKey = dGVzdGtleWZvcnRlc3RpbmcxMjM0NTY3ODlhYmNkZWZnaGlqaw==
Endpoint = 192.168.1.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`

	tmpfile, err := os.CreateTemp("", "wg-config-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(configContent)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	// Test parsing
	config, err := ParseWireGuardConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// Validate interface config
	if config.Interface.PrivateKey != "YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==" {
		t.Errorf("Expected private key to match")
	}

	if config.Interface.Address.String() != "10.0.0.2/24" {
		t.Errorf("Expected address 10.0.0.2/24, got %s", config.Interface.Address.String())
	}

	if config.Interface.ListenPort != 51820 {
		t.Errorf("Expected listen port 51820, got %d", config.Interface.ListenPort)
	}

	if config.Interface.MTU != 1420 {
		t.Errorf("Expected MTU 1420, got %d", config.Interface.MTU)
	}

	// Validate peer config
	if len(config.Peers) != 1 {
		t.Fatalf("Expected 1 peer, got %d", len(config.Peers))
	}

	peer := config.Peers[0]
	if peer.PublicKey != "dGVzdGtleWZvcnRlc3RpbmcxMjM0NTY3ODlhYmNkZWZnaGlqaw==" {
		t.Errorf("Expected peer public key to match")
	}

	if peer.Endpoint.String() != "192.168.1.1:51820" {
		t.Errorf("Expected endpoint 192.168.1.1:51820, got %s", peer.Endpoint.String())
	}

	if len(peer.AllowedIPs) != 1 {
		t.Fatalf("Expected 1 allowed IP, got %d", len(peer.AllowedIPs))
	}

	if peer.AllowedIPs[0].String() != "0.0.0.0/0" {
		t.Errorf("Expected allowed IP 0.0.0.0/0, got %s", peer.AllowedIPs[0].String())
	}

	if peer.PersistentKeepalive != 25 {
		t.Errorf("Expected persistent keepalive 25, got %d", peer.PersistentKeepalive)
	}
}

func TestParseWireGuardConfigMissingFields(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name:    "missing private key",
			config:  "[Interface]\nAddress = 10.0.0.2/24\n",
			wantErr: "missing private key",
		},
		{
			name:    "missing address",
			config:  "[Interface]\nPrivateKey = YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==\n",
			wantErr: "missing address",
		},
		{
			name:    "no peers",
			config:  "[Interface]\nPrivateKey = YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==\nAddress = 10.0.0.2/24\n",
			wantErr: "no peers configured",
		},
		{
			name:    "invalid private key",
			config:  "[Interface]\nPrivateKey = invalid-key\nAddress = 10.0.0.2/24\n[Peer]\nPublicKey = dGVzdGtleWZvcnRlc3RpbmcxMjM0NTY3ODlhYmNkZWZnaGlqaw==\n",
			wantErr: "invalid private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile, err := os.CreateTemp("", "wg-config-*.conf")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpfile.Name())

			if _, err := tmpfile.Write([]byte(tt.config)); err != nil {
				t.Fatal(err)
			}
			tmpfile.Close()

			_, err = ParseWireGuardConfig(tmpfile.Name())
			if err == nil {
				t.Errorf("Expected error containing '%s', but got no error", tt.wantErr)
			} else if err.Error() == "" || len(err.Error()) < 3 {
				t.Errorf("Expected meaningful error message, got: %v", err)
			}
		})
	}
}

func TestParseInterfaceConfig(t *testing.T) {
	config := &InterfaceConfig{MTU: 1420}

	tests := []struct {
		key   string
		value string
		check func(*testing.T, *InterfaceConfig)
	}{
		{
			key:   "privatekey",
			value: "YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==",
			check: func(t *testing.T, c *InterfaceConfig) {
				if c.PrivateKey != "YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==" {
					t.Errorf("Private key not set correctly")
				}
			},
		},
		{
			key:   "address",
			value: "10.0.0.2/24",
			check: func(t *testing.T, c *InterfaceConfig) {
				if c.Address == nil || c.Address.String() != "10.0.0.2/24" {
					t.Errorf("Address not set correctly")
				}
			},
		},
		{
			key:   "listenport",
			value: "51820",
			check: func(t *testing.T, c *InterfaceConfig) {
				if c.ListenPort != 51820 {
					t.Errorf("Listen port not set correctly")
				}
			},
		},
		{
			key:   "mtu",
			value: "1500",
			check: func(t *testing.T, c *InterfaceConfig) {
				if c.MTU != 1500 {
					t.Errorf("MTU not set correctly")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			err := parseInterfaceConfig(config, tt.key, tt.value)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			tt.check(t, config)
		})
	}
}

func TestParsePeerConfig(t *testing.T) {
	config := &PeerConfig{}

	// Test public key
	err := parsePeerConfig(config, "publickey", "dGVzdGtleWZvcnRlc3RpbmcxMjM0NTY3ODlhYmNkZWZnaGlqaw==")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if config.PublicKey != "dGVzdGtleWZvcnRlc3RpbmcxMjM0NTY3ODlhYmNkZWZnaGlqaw==" {
		t.Errorf("Public key not set correctly")
	}

	// Test endpoint
	err = parsePeerConfig(config, "endpoint", "192.168.1.1:51820")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if config.Endpoint == nil || config.Endpoint.String() != "192.168.1.1:51820" {
		t.Errorf("Endpoint not set correctly")
	}

	// Test allowed IPs
	err = parsePeerConfig(config, "allowedips", "0.0.0.0/0, 192.168.1.0/24")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(config.AllowedIPs) != 2 {
		t.Errorf("Expected 2 allowed IPs, got %d", len(config.AllowedIPs))
	}

	// Test persistent keepalive
	err = parsePeerConfig(config, "persistentkeepalive", "25")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if config.PersistentKeepalive != 25 {
		t.Errorf("Persistent keepalive not set correctly")
	}
}

func TestParseAllowedIPs(t *testing.T) {
	config := &PeerConfig{}

	// Test various IP formats
	tests := []struct {
		input    string
		expected int
	}{
		{"0.0.0.0/0", 1},
		{"192.168.1.0/24", 1},
		{"10.0.0.1", 1}, // Single IP should become /32
		{"192.168.1.0/24, 10.0.0.0/8", 2},
		{"8.8.8.8, 1.1.1.1", 2},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			config.AllowedIPs = nil // Reset
			err := parsePeerConfig(config, "allowedips", tt.input)
			if err != nil {
				t.Errorf("Unexpected error for input '%s': %v", tt.input, err)
			}
			if len(config.AllowedIPs) != tt.expected {
				t.Errorf("Expected %d allowed IPs for input '%s', got %d", tt.expected, tt.input, len(config.AllowedIPs))
			}
		})
	}
}

func TestConfigFileNotExists(t *testing.T) {
	_, err := ParseWireGuardConfig("/nonexistent/file.conf")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}
