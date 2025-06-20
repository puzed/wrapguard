#!/bin/bash
set -e

echo "🔑 Generating WireGuard keys..."

# Create keys directory
mkdir -p /workspace/keys

# Generate keys for each peer
for peer in wg-server node-server-1 node-server-2; do
    echo "Generating keys for $peer..."
    wg genkey > /workspace/keys/${peer}_private.key
    wg pubkey < /workspace/keys/${peer}_private.key > /workspace/keys/${peer}_public.key
    echo "✅ Keys generated for $peer"
done

# Generate preshared keys for each client-server pair
echo "Generating preshared keys..."
wg genpsk > /workspace/keys/server_node1_preshared.key
wg genpsk > /workspace/keys/server_node2_preshared.key

# Set proper permissions
chmod 600 /workspace/keys/*_private.key
chmod 644 /workspace/keys/*_public.key
chmod 600 /workspace/keys/*_preshared.key

echo ""
echo "📋 Generated keys:"
echo "=================="
for peer in wg-server node-server-1 node-server-2; do
    echo "$peer:"
    echo "  Public:  $(cat /workspace/keys/${peer}_public.key)"
    echo ""
done

# Generate configuration files
echo "📝 Generating WireGuard configurations..."

# Read keys
WG_SERVER_PRIVATE=$(cat /workspace/keys/wg-server_private.key)
WG_SERVER_PUBLIC=$(cat /workspace/keys/wg-server_public.key)
NODE1_PRIVATE=$(cat /workspace/keys/node-server-1_private.key)
NODE1_PUBLIC=$(cat /workspace/keys/node-server-1_public.key)
NODE2_PRIVATE=$(cat /workspace/keys/node-server-2_private.key)
NODE2_PUBLIC=$(cat /workspace/keys/node-server-2_public.key)
PSK_1=$(cat /workspace/keys/server_node1_preshared.key)
PSK_2=$(cat /workspace/keys/server_node2_preshared.key)

# Create configs directory
mkdir -p /workspace/configs

# Generate wg-server config
cat > /workspace/configs/wg-server.conf <<EOF
[Interface]
PrivateKey = $WG_SERVER_PRIVATE
Address = 10.150.0.1/24
ListenPort = 51820

[Peer]
# node-server-1
PublicKey = $NODE1_PUBLIC
PresharedKey = $PSK_1
AllowedIPs = 10.150.0.2/32

[Peer]
# node-server-2
PublicKey = $NODE2_PUBLIC
PresharedKey = $PSK_2
AllowedIPs = 10.150.0.3/32
EOF

# Generate node-server-1 config
cat > /workspace/configs/node-server-1.conf <<EOF
[Interface]
PrivateKey = $NODE1_PRIVATE
Address = 10.150.0.2/24

[Peer]
PublicKey = $WG_SERVER_PUBLIC
PresharedKey = $PSK_1
Endpoint = wg-server:51820
AllowedIPs = 10.150.0.0/24
PersistentKeepalive = 25
EOF

# Generate node-server-2 config
cat > /workspace/configs/node-server-2.conf <<EOF
[Interface]
PrivateKey = $NODE2_PRIVATE
Address = 10.150.0.3/24

[Peer]
PublicKey = $WG_SERVER_PUBLIC
PresharedKey = $PSK_2
Endpoint = wg-server:51820
AllowedIPs = 10.150.0.0/24
PersistentKeepalive = 25
EOF

# Set proper permissions
chmod 600 /workspace/configs/*.conf

echo "✅ Configuration files generated"