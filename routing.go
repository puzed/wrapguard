package main

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// RoutingPolicy defines a policy for routing traffic through a specific peer
type RoutingPolicy struct {
	DestinationCIDR string    // e.g., "192.168.1.0/24" or "0.0.0.0/0"
	Protocol        string    // "tcp", "udp", or "any"
	PortRange       PortRange // Port range for the policy
	Priority        int       // Higher priority policies are evaluated first
}

// PortRange represents a range of ports
type PortRange struct {
	Start int
	End   int
}

// RoutingEngine manages routing decisions for WireGuard peers
type RoutingEngine struct {
	peers      []PeerConfig
	routeTable map[string][]int       // CIDR -> peer indices
	allowedIPs map[int][]netip.Prefix // peer index -> allowed IP prefixes
}

// NewRoutingEngine creates a new routing engine from the WireGuard configuration
func NewRoutingEngine(config *WireGuardConfig) *RoutingEngine {
	engine := &RoutingEngine{
		peers:      config.Peers,
		routeTable: make(map[string][]int),
		allowedIPs: make(map[int][]netip.Prefix),
	}

	// Build routing table from AllowedIPs
	for peerIdx, peer := range config.Peers {
		for _, allowedIP := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(allowedIP)
			if err != nil {
				if logger != nil {
					logger.Warnf("Invalid AllowedIP %s for peer %d: %v", allowedIP, peerIdx, err)
				}
				continue
			}
			engine.allowedIPs[peerIdx] = append(engine.allowedIPs[peerIdx], prefix)
		}

		// Process routing policies
		for _, policy := range peer.RoutingPolicies {
			if existingPeers, exists := engine.routeTable[policy.DestinationCIDR]; exists {
				engine.routeTable[policy.DestinationCIDR] = append(existingPeers, peerIdx)
			} else {
				engine.routeTable[policy.DestinationCIDR] = []int{peerIdx}
			}
		}
	}

	return engine
}

// FindPeerForDestination finds the appropriate peer for routing to a destination
func (r *RoutingEngine) FindPeerForDestination(dstIP net.IP, dstPort int, protocol string) (*PeerConfig, int) {
	// Convert to netip.Addr for easier comparison
	var addr netip.Addr
	if dstIP.To4() != nil {
		// Ensure we use IPv4 representation
		addr, _ = netip.AddrFromSlice(dstIP.To4())
	} else {
		addr, _ = netip.AddrFromSlice(dstIP)
	}
	if !addr.IsValid() {
		return nil, -1
	}

	// First, check routing policies
	bestPeer := -1
	bestPriority := -1
	bestSpecificity := -1

	for cidr, peerIndices := range r.routeTable {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}

		if prefix.Contains(addr) {
			specificity := prefix.Bits()

			for _, peerIdx := range peerIndices {
				if peerIdx >= len(r.peers) {
					continue
				}

				peer := &r.peers[peerIdx]

				// Check if this peer has a matching routing policy
				for _, policy := range peer.RoutingPolicies {
					if policy.DestinationCIDR != cidr {
						continue
					}

					// Check protocol match
					if policy.Protocol != "any" && policy.Protocol != protocol {
						continue
					}

					// Check port range
					if dstPort > 0 && (dstPort < policy.PortRange.Start || dstPort > policy.PortRange.End) {
						continue
					}

					// This policy matches, check if it's better than current best
					if specificity > bestSpecificity ||
						(specificity == bestSpecificity && policy.Priority > bestPriority) {
						bestPeer = peerIdx
						bestPriority = policy.Priority
						bestSpecificity = specificity
					}
				}
			}
		}
	}

	if bestPeer >= 0 {
		return &r.peers[bestPeer], bestPeer
	}

	// If no routing policy matched, fall back to AllowedIPs
	for peerIdx, prefixes := range r.allowedIPs {
		for _, prefix := range prefixes {
			if prefix.Contains(addr) {
				return &r.peers[peerIdx], peerIdx
			}
		}
	}

	return nil, -1
}

// ParsePortRange parses a port range string like "80", "8080-9000", or "any"
func ParsePortRange(portStr string) (PortRange, error) {
	if portStr == "" || portStr == "any" {
		return PortRange{Start: 1, End: 65535}, nil
	}

	if strings.Contains(portStr, "-") {
		parts := strings.Split(portStr, "-")
		if len(parts) != 2 {
			return PortRange{}, fmt.Errorf("invalid port range format: %s", portStr)
		}

		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return PortRange{}, fmt.Errorf("invalid start port: %s", parts[0])
		}

		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return PortRange{}, fmt.Errorf("invalid end port: %s", parts[1])
		}

		if start > end || start < 1 || end > 65535 {
			return PortRange{}, fmt.Errorf("invalid port range: %d-%d", start, end)
		}

		return PortRange{Start: start, End: end}, nil
	}

	// Single port
	port, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid port: %s", portStr)
	}

	if port < 1 || port > 65535 {
		return PortRange{}, fmt.Errorf("port out of range: %d", port)
	}

	return PortRange{Start: port, End: port}, nil
}

// ParseRoutingPolicy parses a routing policy string
// Format: "CIDR" or "CIDR:protocol:ports"
// Examples: "192.168.1.0/24", "0.0.0.0/0:tcp:80,443", "10.0.0.0/8:any:8080-9000"
func ParseRoutingPolicy(policyStr string, priority int) (*RoutingPolicy, error) {
	parts := strings.Split(policyStr, ":")

	if len(parts) == 0 || parts[0] == "" {
		return nil, fmt.Errorf("empty routing policy")
	}

	policy := &RoutingPolicy{
		DestinationCIDR: parts[0],
		Protocol:        "any",
		PortRange:       PortRange{Start: 1, End: 65535},
		Priority:        priority,
	}

	// Validate CIDR
	if _, err := netip.ParsePrefix(policy.DestinationCIDR); err != nil {
		return nil, fmt.Errorf("invalid CIDR: %s", policy.DestinationCIDR)
	}

	if len(parts) > 1 {
		// Protocol specified
		protocol := strings.ToLower(parts[1])
		if protocol != "tcp" && protocol != "udp" && protocol != "any" {
			return nil, fmt.Errorf("invalid protocol: %s", protocol)
		}
		policy.Protocol = protocol
	}

	if len(parts) > 2 {
		// Port range specified
		portRange, err := ParsePortRange(parts[2])
		if err != nil {
			return nil, err
		}
		policy.PortRange = portRange
	}

	return policy, nil
}
