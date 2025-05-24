# WrapGuard - Userspace WireGuard Proxy

WrapGuard enables any application to transparently route ALL network traffic through a WireGuard VPN without requiring container privileges or kernel modules.

## Features

- **Pure Userspace**: No TUN interface creation, no NET_ADMIN capability needed
- **Transparent Interception**: Uses LD_PRELOAD to intercept all network calls
- **Bidirectional Support**: Both incoming and outgoing connections work
- **Standard Config**: Uses standard WireGuard configuration files

## Building

```bash
make build
```

This will create:
- `wrapguard` - The main executable
- `libwrapguard.so` - The LD_PRELOAD library

## Usage

```bash
# Route outgoing connections through WireGuard
wrapguard --config=~/wg0.conf -- curl https://icanhazip.com

# Route incoming connections through WireGuard
wrapguard --config=~/wg0.conf -- node -e 'http.createServer().listen(8080)'
```

## Configuration

WrapGuard uses standard WireGuard configuration files:

```ini
[Interface]
PrivateKey = <your-private-key>
Address = 10.0.0.2/24

[Peer]
PublicKey = <server-public-key>
Endpoint = server.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

## How It Works

1. **Main Process**: Parses config, initializes WireGuard userspace implementation
2. **LD_PRELOAD Library**: Intercepts network system calls (socket, connect, send, recv, etc.)
3. **Virtual Network Stack**: Routes packets between intercepted connections and WireGuard tunnel
4. **Memory-based TUN**: No kernel interface needed, packets processed entirely in memory

## Limitations

- Currently only supports IPv4
- TCP and UDP protocols only
- Performance overhead due to userspace packet processing

## Testing

```bash
# Test outgoing connection
wrapguard --config=example-wg0.conf -- curl https://example.com

# Test incoming connection
wrapguard --config=example-wg0.conf -- python3 -m http.server 8080
```
