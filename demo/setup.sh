#!/bin/bash

rm -rf keys/ configs/ wrapguard-src

set -e

echo "🔐 WrapGuard Demo Setup"
echo "======================"
echo ""
echo "This script prepares everything needed for the WrapGuard demo."
echo "No WireGuard installation required on your host!"
echo ""

# Step 1: Prepare wrapguard source for Docker build
echo "📦 Preparing wrapguard source for Docker build..."
mkdir -p wrapguard-src

# Copy necessary files from parent directory
cp ../*.go wrapguard-src/ 2>/dev/null || true
cp ../go.mod wrapguard-src/
cp ../go.sum wrapguard-src/
cp ../Makefile wrapguard-src/
cp -r ../lib wrapguard-src/

echo "✅ Source files copied to wrapguard-src/"
echo ""

# Step 2: Build and run the key generation container
echo "🐳 Building key generation container..."
docker build -f Dockerfile.keygen -t wrapguard-keygen .

echo ""
echo "🔑 Running key generation..."
docker run --rm -v "$(pwd):/workspace" wrapguard-keygen

echo ""
echo "✅ Setup complete! Everything is ready."
echo ""
echo "📁 Generated files:"
echo "  - wrapguard-src/  (Source code for building)"
echo "  - keys/           (WireGuard private/public keys)"
echo "  - configs/        (WireGuard configuration files)"
echo ""
echo "🚀 Next step: docker compose up --build"