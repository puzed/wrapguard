#!/bin/bash

# Example usage of WrapGuard with routing options

echo "Example 1: Using exit node to route all traffic through a specific peer"
echo "wrapguard --config=wg0.conf --exit-node=10.150.0.3 -- curl https://icanhazip.com"
echo ""

echo "Example 2: Routing specific subnets through different peers"
echo "wrapguard --config=wg0.conf \\"
echo "  --route=192.168.0.0/16:10.150.0.3 \\"
echo "  --route=172.16.0.0/12:10.150.0.4 \\"
echo "  -- ssh internal.corp.com"
echo ""

echo "Example 3: Combining exit node with specific routes"
echo "wrapguard --config=wg0.conf \\"
echo "  --exit-node=10.150.0.5 \\"
echo "  --route=10.0.0.0/8:10.150.0.3 \\"
echo "  -- curl https://example.com"
echo ""

echo "Note: The peer IPs (like 10.150.0.3) must be within the AllowedIPs range of the corresponding peer in your config."