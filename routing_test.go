package main

import (
	"net"
	"testing"
)

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		input    string
		expected PortRange
		hasError bool
	}{
		{"80", PortRange{Start: 80, End: 80}, false},
		{"8080-9000", PortRange{Start: 8080, End: 9000}, false},
		{"any", PortRange{Start: 1, End: 65535}, false},
		{"", PortRange{Start: 1, End: 65535}, false},
		{"invalid", PortRange{}, true},
		{"80-70", PortRange{}, true},
		{"0-100", PortRange{}, true},
		{"100-70000", PortRange{}, true},
	}

	for _, test := range tests {
		result, err := ParsePortRange(test.input)
		if test.hasError {
			if err == nil {
				t.Errorf("Expected error for input %s, but got none", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for input %s: %v", test.input, err)
			}
			if result != test.expected {
				t.Errorf("For input %s, expected %v but got %v", test.input, test.expected, result)
			}
		}
	}
}

func TestParseRoutingPolicy(t *testing.T) {
	tests := []struct {
		input    string
		priority int
		expected RoutingPolicy
		hasError bool
	}{
		{
			"192.168.1.0/24",
			0,
			RoutingPolicy{
				DestinationCIDR: "192.168.1.0/24",
				Protocol:        "any",
				PortRange:       PortRange{Start: 1, End: 65535},
				Priority:        0,
			},
			false,
		},
		{
			"0.0.0.0/0:tcp:80",
			1,
			RoutingPolicy{
				DestinationCIDR: "0.0.0.0/0",
				Protocol:        "tcp",
				PortRange:       PortRange{Start: 80, End: 80},
				Priority:        1,
			},
			false,
		},
		{
			"10.0.0.0/8:udp:5000-6000",
			2,
			RoutingPolicy{
				DestinationCIDR: "10.0.0.0/8",
				Protocol:        "udp",
				PortRange:       PortRange{Start: 5000, End: 6000},
				Priority:        2,
			},
			false,
		},
		{
			"invalid-cidr",
			0,
			RoutingPolicy{},
			true,
		},
		{
			"192.168.1.0/24:invalid-protocol:80",
			0,
			RoutingPolicy{},
			true,
		},
	}

	for _, test := range tests {
		result, err := ParseRoutingPolicy(test.input, test.priority)
		if test.hasError {
			if err == nil {
				t.Errorf("Expected error for input %s, but got none", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for input %s: %v", test.input, err)
			}
			if result == nil {
				t.Errorf("Expected non-nil result for input %s", test.input)
			} else if *result != test.expected {
				t.Errorf("For input %s, expected %+v but got %+v", test.input, test.expected, *result)
			}
		}
	}
}

func TestRoutingEngine(t *testing.T) {
	// Create a test configuration
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			Address: "10.150.0.2/24",
		},
		Peers: []PeerConfig{
			{
				PublicKey:  "peer1",
				Endpoint:   "vpn1.example.com:51820",
				AllowedIPs: []string{"0.0.0.0/0"},
				RoutingPolicies: []RoutingPolicy{
					{
						DestinationCIDR: "0.0.0.0/0",
						Protocol:        "any",
						PortRange:       PortRange{Start: 1, End: 65535},
						Priority:        0,
					},
				},
			},
			{
				PublicKey:  "peer2",
				Endpoint:   "vpn2.example.com:51820",
				AllowedIPs: []string{"192.168.0.0/16", "172.16.0.0/12"},
				RoutingPolicies: []RoutingPolicy{
					{
						DestinationCIDR: "192.168.1.0/24",
						Protocol:        "tcp",
						PortRange:       PortRange{Start: 80, End: 443},
						Priority:        1,
					},
					{
						DestinationCIDR: "0.0.0.0/0",
						Protocol:        "tcp",
						PortRange:       PortRange{Start: 8080, End: 9000},
						Priority:        2,
					},
				},
			},
			{
				PublicKey:  "peer3",
				Endpoint:   "dev-vpn.example.com:51820",
				AllowedIPs: []string{"10.0.0.0/8"},
				RoutingPolicies: []RoutingPolicy{
					{
						DestinationCIDR: "10.0.0.0/8",
						Protocol:        "any",
						PortRange:       PortRange{Start: 1, End: 65535},
						Priority:        0,
					},
				},
			},
		},
	}

	engine := NewRoutingEngine(config)

	tests := []struct {
		name         string
		dstIP        string
		dstPort      int
		protocol     string
		expectedPeer int
	}{
		{"General traffic", "8.8.8.8", 53, "udp", 0},
		{"HTTP to 192.168.1.x", "192.168.1.100", 80, "tcp", 1},
		{"HTTPS to 192.168.1.x", "192.168.1.100", 443, "tcp", 1},
		{"Port 8080 to any IP", "1.2.3.4", 8080, "tcp", 1},
		{"Development network", "10.1.2.3", 3000, "tcp", 2},
		{"SSH to 192.168.1.x (no specific rule)", "192.168.1.100", 22, "tcp", 0},
		{"UDP to port 8080 (TCP-only rule)", "1.2.3.4", 8080, "udp", 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ip := net.ParseIP(test.dstIP)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", test.dstIP)
			}

			peer, peerIdx := engine.FindPeerForDestination(ip, test.dstPort, test.protocol)
			if peerIdx != test.expectedPeer {
				t.Errorf("Expected peer %d, but got peer %d", test.expectedPeer, peerIdx)
			}
			if test.expectedPeer >= 0 && peer == nil {
				t.Errorf("Expected non-nil peer for peer index %d", test.expectedPeer)
			}
		})
	}
}
