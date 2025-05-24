#!/bin/bash

# Enable color output
export TERM=xterm-256color

echo "=== WrapGuard Demo ==="
echo

echo "1. Showing help screen:"
echo "----------------------"
./wrapguard --help

echo
echo
echo "2. Showing version:"
echo "------------------"
./wrapguard --version

echo
echo
echo "3. Running without config (shows help):"
echo "--------------------------------------"
./wrapguard 2>&1 || true

echo
echo
echo "4. Example with config file:"
echo "---------------------------"
echo "./wrapguard --config=example-wg0.conf -- echo 'Hello from WireGuard tunnel!'"