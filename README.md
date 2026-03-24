# WrapGuard - Userspace WireGuard Proxy

WrapGuard enables applications to route network traffic through a WireGuard VPN from userspace without requiring container privileges or kernel modules.

Linux is the primary production target today. macOS build, packaging, and regression checks run in CI, and the macOS runtime path has proven direct-launch TCP routing for CLI targets, but it is still experimental and limited to targets that can accept injection.

## Features

- **Pure Userspace**: No TUN interface creation, no NET_ADMIN capability needed
- **Transparent Interception**: Uses platform-specific dynamic library injection on supported hosts
- **Bidirectional Support**: Both incoming and outgoing connections work on supported Linux builds
- **Standard Config**: Uses standard WireGuard configuration files

## Installation

### Pre-compiled Binaries

Download pre-compiled binaries for Linux and macOS from the [releases page](https://github.com/puzed/wrapguard/releases).

Linux releases are production-targeted. macOS archives are packaged and validated for layout consistency plus release-archive smoke checks, but macOS support should still be treated as experimental until the runtime launcher work is complete.

**No additional dependencies required** - WrapGuard is a single binary that includes everything needed to create WireGuard connections. You don't need WireGuard installed on your host machine, kernel modules, or any other VPN software.

### Building from Source

```bash
make build
```

This will create:
- `wrapguard` - The main executable
- `libwrapguard.so` on Linux or `libwrapguard.dylib` on macOS - the injected library that lives next to the binary

## Support Matrix

- Linux `amd64` and `arm64`: supported for production use.
- macOS 14 Sonoma and macOS 15 Sequoia on `amd64` and `arm64`: experimental direct-launch support for targets that can be launched as an executable path.
- If you are experimenting with a simple `.app` bundle, WrapGuard can resolve the inner executable when `Contents/MacOS` contains a single clear candidate; `open -a` remains unsupported.
- Direct CLI launches through a non-SIP shell binary are supported in the same experimental sense as other direct macOS CLI targets.
- `open -a` and launch targets that depend on Apple-managed app launchers: unsupported.
- macOS releases newer than Sequoia may work, but they are not yet part of the documented QA matrix.
- macOS SIP-protected binaries in locations such as `/usr/bin`, `/bin`, `/System`, `/sbin`, and `/usr/libexec`: rejected before launch and unsupported.
- Third-party signed GUI apps, hardened-runtime apps, sandboxed helpers, and browser-style multi-process apps may still launch but are not supported and may be unstable under injection.
- Routed outbound TCP is the documented and tested macOS path today. UDP is not tunneled on macOS, and WrapGuard may intentionally suppress likely QUIC `UDP/443` connect attempts so browsers fall back to the TCP path instead of leaking through UDP.
- IPv6 remains outside the production support statement on macOS.
- Windows: unsupported.

## Usage

```bash
# Route incoming connections through WireGuard
wrapguard --config=~/wg0.conf -- node -e 'http.createServer((_, res) => res.end("hello")).listen(8080)'

# Route outgoing connections through WireGuard
wrapguard --config=~/wg1.conf -- curl http://10.0.0.3:8080

# Use an exit node (route all traffic through a specific peer)
wrapguard --config=~/wg0.conf --exit-node=10.150.0.3 -- curl https://icanhazip.com

# Route specific subnets through different peers
wrapguard --config=~/wg0.conf \
  --route=192.168.0.0/16:10.150.0.3 \
  --route=172.16.0.0/12:10.150.0.4 \
  -- curl https://internal.corp.com

# With debug logging to console
wrapguard --config=~/wg0.conf --log-level=debug -- curl https://icanhazip.com

# With logging to file
wrapguard --config=~/wg0.conf --log-level=info --log-file=/tmp/wrapguard.log -- curl https://icanhazip.com
```

## macOS Guide

- Launch the target executable directly with WrapGuard.
- For a simple `.app` bundle with a single clear executable in `Contents/MacOS`, you can also pass the bundle path and WrapGuard will resolve the inner executable for you.
- If a bundle contains multiple executable candidates in `Contents/MacOS`, WrapGuard will fail closed and ask you to launch the inner executable explicitly.
- If you want a shell session under WrapGuard on macOS, use a non-SIP shell binary launched directly by WrapGuard. Apple-protected shells in `/bin` are not a supported injection target.
- `open -a AppName` is not equivalent to launching the inner executable directly and is not a supported wrapping path.
- Apple-protected binaries in locations such as `/usr/bin`, `/bin`, `/System`, `/sbin`, and `/usr/libexec` are blocked by SIP and are unsupported.
- Browser-style GUI apps such as Firefox/LibreWolf-class multi-process browsers are still experimental even when TCP interception works. Helper, GPU, compositor, and sandboxed subprocesses may become unstable under DYLD injection.
- If a browser-style app shows different results on soft refresh versus hard refresh, treat that as a sign that the app may be using cache, service-worker, or alternate transport paths rather than assuming the tunnel path itself is broken.
- Routed outbound TCP is the documented and tested macOS path today. Wrapped UDP and wrapped IPv6 traffic are not yet production-ready on macOS, and broader non-blocking/browser socket compatibility is still under active validation even though wrapped TCP sockets now virtualize `getpeername()`.
- DNS lookups are still resolved by the host network stack. WrapGuard currently routes post-resolution IP-literal TCP destinations through the tunnel, but it does not intercept resolver APIs or tunnel DNS itself.
- Localhost and loopback traffic are intentionally left on the host stack and are not routed through the injected SOCKS path.

### macOS Troubleshooting

- Run `wrapguard --doctor [target]` to check the local runtime layout, selected injection mode, and macOS preflight restrictions before you try a real launch.
- If you pass a target, `--doctor` also validates that launch target before WrapGuard starts the tunnel stack. If you omit the target, it only checks the local runtime artifacts.
- `--doctor` accepts resolvable `.app` bundles, prints the inner executable it selected, and still rejects SIP-protected launch paths on macOS before launch.
- Run `wrapguard --config=<path> --self-test` to validate that WrapGuard can start its IPC/SOCKS stack, inject the library, and observe an intercepted outbound `connect()`.
- If the child starts but WrapGuard reports that the interceptor never announced readiness, confirm that the target is not SIP-protected and that `libwrapguard.dylib` is present next to `wrapguard`.
- If traffic is unchanged, rerun with `--log-level=debug` and check for the startup lines showing `DYLD_INSERT_LIBRARIES`, the resolved dylib path, and the interceptor load message.
- If a hostname-based connection still resolves through the host instead of the VPN, that is expected today. WrapGuard only routes the resulting IP-literal TCP destination through SOCKS and the WireGuard userspace netstack.
- If you see the interceptor load and outbound `connect()` calls being intercepted but the request still exits with the host IP, treat that as a tunnel-path failure. Routed outbound TCP now fails through the WireGuard userspace netstack instead of silently falling back to a direct host connection, so this points to peer reachability, exit-node routing, or upstream WireGuard configuration rather than dylib injection.
- If you are validating a browser-like app and it still reports the host IP after a soft refresh, compare it against a hard refresh and a direct CLI probe such as `curl`; browser caching, service workers, QUIC/HTTP3, or helper-process instability can all change the observed path.
- If codesigning or hardened runtime prevents injection, use an unsigned or developer-controlled binary for now. Notarized and hardened-runtime compatibility is not part of the current experimental support statement.
- If a browser or GUI app loads, intercepts some traffic, and then crashes later, treat that as a helper-process compatibility issue rather than proof that the tunnel path is broken.

## Routing

WrapGuard supports policy-based routing to direct traffic through specific WireGuard peers.

### Exit Node

Use the `--exit-node` option to route all traffic through a specific peer (like a traditional VPN):

```bash
wrapguard --config=~/wg0.conf --exit-node=10.150.0.3 -- curl https://example.com
```

### Policy-Based Routing

Use the `--route` option to route specific subnets through different peers:

```bash
# Route corporate traffic through one peer, internet through another
wrapguard --config=~/wg0.conf \
  --route=192.168.0.0/16:10.150.0.3 \
  --route=0.0.0.0/0:10.150.0.4 \
  -- ssh internal.corp.com
```

### Configuration File Routing

You can also define routes in your WireGuard configuration file:

```ini
[Peer]
PublicKey = ...
AllowedIPs = 10.150.0.0/24
# Route all traffic through this peer
Route = 0.0.0.0/0
# Or route specific subnets
Route = 192.168.0.0/16
Route = 172.16.0.0/12:tcp:443
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
2. **Injected Library**: Intercepts network system calls using the host-specific dynamic loading path
3. **Virtual Network Stack**: Routes packets between intercepted connections and WireGuard tunnel
4. **Userspace TUN/Netstack**: No kernel interface needed, packets are handled entirely in memory by the WireGuard userspace netstack

## Limitations

- Linux and macOS only (Windows is not supported)
- macOS runtime support is experimental and should not be assumed for SIP-protected binaries, hardened-runtime apps, `open -a` launcher paths, or launch targets that cannot accept injected libraries
- Routed TCP is the primary documented path today
- Wrapped UDP and wrapped IPv6 are not yet documented as supported on macOS
- Performance overhead due to userspace packet processing

## Development

### Running Tests

WrapGuard includes comprehensive unit tests for all core functionality:

```bash
# Run all tests
go test -v ./...

# Run tests with coverage
go test -cover ./...
```

### Building

```bash
# Build the main binary
make build

# Validate a local macOS package layout end to end
make smoke-macos

# Build with debug information
make debug

# Clean build artifacts
make clean
```

## Demo

WrapGuard includes a comprehensive Docker-based demo that shows Node.js applications communicating through a WireGuard tunnel without requiring root privileges or kernel modules.

The demo consists of:
- A WireGuard server container
- Two Node.js HTTP servers wrapped with WrapGuard
- Cross-server communication through the WireGuard tunnel

### Running the Demo

```bash
cd demo
./setup.sh
docker compose up --build
```

## Testing

```bash
# Test outgoing connection
wrapguard --config=example-wg0.conf -- curl https://example.com

# Test incoming connection
wrapguard --config=example-wg0.conf -- python3 -m http.server 8080
```
