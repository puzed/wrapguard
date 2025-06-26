#!/bin/bash

# Demo script for testing policy-based routing

echo "=== WrapGuard Policy-Based Routing Demo ==="
echo ""
echo "This demo shows how WrapGuard routes traffic through different peers"
echo "based on destination IP, protocol, and port."
echo ""

# Check if wrapguard is built
if [ ! -f "./wrapguard" ]; then
    echo "Building wrapguard..."
    make build
fi

# Enable debug logging
export WRAPGUARD_DEBUG=1

echo "1. Testing general traffic routing (should go through peer 1):"
echo "   Command: wrapguard --config=example-policy-routing.conf --log-level=debug -- curl -s https://icanhazip.com"
echo ""

echo "2. Testing port 8080 routing (should go through peer 2):"
echo "   Command: wrapguard --config=example-policy-routing.conf --log-level=debug -- curl -s http://example.com:8080"
echo ""

echo "3. Testing development network routing (should go through peer 3):"
echo "   Command: wrapguard --config=example-policy-routing.conf --log-level=debug -- ping -c 1 10.1.2.3"
echo ""

echo "Note: The actual commands won't work without real WireGuard peers configured,"
echo "but the debug logs will show which peer would be selected for each connection."