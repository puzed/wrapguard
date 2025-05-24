#!/bin/bash

echo "WrapGuard Test Script"
echo "===================="

# Check if binaries exist
if [ ! -f "wrapguard" ]; then
    echo "Error: wrapguard binary not found. Run 'make build' first."
    exit 1
fi

if [ ! -f "libwrapguard.so" ]; then
    echo "Error: libwrapguard.so not found. Run 'make build' first."
    exit 1
fi

echo "✓ Binaries found"

# Test 1: Show help
echo -e "\nTest 1: Show usage"
./wrapguard || true

# Test 2: Try with a simple command (without actual WireGuard connection)
echo -e "\nTest 2: Run echo command through wrapguard"
./wrapguard --config=example-wg0.conf -- echo "Hello from wrapguard!"

echo -e "\nBasic tests completed!"