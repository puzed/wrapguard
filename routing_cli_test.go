package main

import (
	"testing"
)

func TestApplyCLIRoutes(t *testing.T) {
	// Create a test configuration
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			PrivateKey: "test-private-key",
			Address:    "10.0.0.2/24",
		},
		Peers: []PeerConfig{
			{
				PublicKey:  "peer1-public-key",
				Endpoint:   "192.168.1.100:51820",
				AllowedIPs: []string{"10.0.0.0/24"},
			},
			{
				PublicKey:  "peer2-public-key",
				Endpoint:   "192.168.1.101:51820",
				AllowedIPs: []string{"10.1.0.0/24"},
			},
		},
	}

	// Test exit node
	err := ApplyCLIRoutes(config, "10.0.0.3", nil)
	if err != nil {
		t.Fatalf("Failed to apply exit node: %v", err)
	}

	// Check that the routing policy was added to the correct peer
	peer1 := &config.Peers[0]
	if len(peer1.RoutingPolicies) != 1 {
		t.Fatalf("Expected 1 routing policy, got %d", len(peer1.RoutingPolicies))
	}

	policy := peer1.RoutingPolicies[0]
	if policy.DestinationCIDR != "0.0.0.0/0" {
		t.Errorf("Expected destination CIDR 0.0.0.0/0, got %s", policy.DestinationCIDR)
	}

	// Test specific routes
	routes := []string{"192.168.1.0/24:10.0.0.4", "172.16.0.0/12:10.1.0.5"}
	err = ApplyCLIRoutes(config, "", routes)
	if err != nil {
		t.Fatalf("Failed to apply routes: %v", err)
	}

	// Check that routes were added to correct peers
	if len(peer1.RoutingPolicies) != 2 {
		t.Fatalf("Expected 2 routing policies on peer1, got %d", len(peer1.RoutingPolicies))
	}

	peer2 := &config.Peers[1]
	if len(peer2.RoutingPolicies) != 1 {
		t.Fatalf("Expected 1 routing policy on peer2, got %d", len(peer2.RoutingPolicies))
	}

	// Verify the specific route on peer2
	if peer2.RoutingPolicies[0].DestinationCIDR != "172.16.0.0/12" {
		t.Errorf("Expected destination CIDR 172.16.0.0/12, got %s", peer2.RoutingPolicies[0].DestinationCIDR)
	}
}

func TestApplyCLIRoutesErrors(t *testing.T) {
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			PrivateKey: "test-private-key",
			Address:    "10.0.0.2/24",
		},
		Peers: []PeerConfig{
			{
				PublicKey:  "peer1-public-key",
				Endpoint:   "192.168.1.100:51820",
				AllowedIPs: []string{"10.0.0.0/24"},
			},
		},
	}

	// Test invalid route format
	err := ApplyCLIRoutes(config, "", []string{"invalid-route"})
	if err == nil {
		t.Error("Expected error for invalid route format")
	}

	// Test invalid CIDR
	err = ApplyCLIRoutes(config, "", []string{"invalid-cidr:10.0.0.3"})
	if err == nil {
		t.Error("Expected error for invalid CIDR")
	}

	// Test peer IP not found
	err = ApplyCLIRoutes(config, "", []string{"192.168.1.0/24:192.168.1.1"})
	if err == nil {
		t.Error("Expected error for peer IP not in any AllowedIPs")
	}
}
