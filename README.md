# WrapGuard - Userspace WireGuard Proxy

WrapGuard enables any application to transparently route ALL network traffic through a WireGuard VPN without requiring container privileges or kernel modules.

## Features

- **Pure Userspace**: No TUN interface creation, no NET_ADMIN capability needed
- **Transparent Interception**: Uses LD_PRELOAD to intercept all network calls
- **Bidirectional Support**: Both incoming and outgoing connections work
- **Standard Config**: Uses standard WireGuard configuration files

## Installation

### Pre-compiled Binaries

Download pre-compiled binaries for common operating systems from the [releases page](https://github.com/puzed/wrapguard/releases).

**No additional dependencies required** - WrapGuard is a single binary that includes everything needed to create WireGuard connections. You don't need WireGuard installed on your host machine, kernel modules, or any other VPN software.

### Building from Source

```bash
make build
```

This will create:
- `wrapguard` - The main executable (single binary with embedded library)
- `libwrapguard.so` - The LD_PRELOAD library

## Usage

```bash
# Route outgoing connections through WireGuard
wrapguard --config=~/wg0.conf -- curl https://icanhazip.com

# Route incoming connections through WireGuard
wrapguard --config=~/wg0.conf -- node -e 'http.createServer().listen(8080)'

# With debug logging to console
wrapguard --config=~/wg0.conf --log-level=debug -- curl https://icanhazip.com

# With logging to file
wrapguard --config=~/wg0.conf --log-level=info --log-file=/tmp/wrapguard.log -- curl https://icanhazip.com
```

## Logging

WrapGuard provides structured JSON logging with configurable levels and output destinations.

### Logging Options

- `--log-level=<level>` - Set logging level (error, warn, info, debug). Default: info
- `--log-file=<path>` - Write logs to file instead of terminal

### Log Levels

- `error` - Only critical errors
- `warn` - Warnings and errors
- `info` - General information, warnings, and errors (default)
- `debug` - Detailed debugging information

### Log Format

All logs are output in structured JSON format with timestamps:

```json
{"timestamp":"2025-05-26T10:00:00Z","level":"info","message":"WrapGuard v1.0.0-dev initialized"}
{"timestamp":"2025-05-26T10:00:00Z","level":"info","message":"Config: example-wg0.conf"}
{"timestamp":"2025-05-26T10:00:00Z","level":"info","message":"Interface: 10.2.0.2/32"}
{"timestamp":"2025-05-26T10:00:00Z","level":"info","message":"Peer endpoint: 192.168.1.8:51820"}
{"timestamp":"2025-05-26T10:00:00Z","level":"info","message":"Launching: curl https://icanhazip.com"}
```

When `--log-file` is specified, all logs are written to the file and nothing appears on the terminal.

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
