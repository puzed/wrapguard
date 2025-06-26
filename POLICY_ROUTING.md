# Policy-Based Routing in WrapGuard

WrapGuard supports policy-based routing, allowing you to route traffic through specific WireGuard peers based on destination IP addresses, protocols, and port ranges.

## Configuration Syntax

In addition to the standard WireGuard configuration, you can add `Route` directives to each peer:

```ini
[Peer]
PublicKey = ...
Endpoint = ...
AllowedIPs = ...
# Route directives for policy-based routing
Route = <CIDR>
Route = <CIDR>:<protocol>:<ports>
```

### Route Format

- `<CIDR>`: Destination network in CIDR notation (e.g., `192.168.1.0/24`, `0.0.0.0/0`)
- `<protocol>`: `tcp`, `udp`, or `any` (optional, defaults to `any`)
- `<ports>`: Port or port range (optional, defaults to all ports)
  - Single port: `80`
  - Port range: `8080-9000`
  - Multiple ports: `80,443` (comma-separated)

## Examples

### Basic Routing by Destination Network

```ini
[Peer]
PublicKey = peer1_public_key
Endpoint = vpn1.example.com:51820
AllowedIPs = 0.0.0.0/0
# Route all traffic through this peer by default
Route = 0.0.0.0/0

[Peer]
PublicKey = peer2_public_key
Endpoint = vpn2.example.com:51820
AllowedIPs = 192.168.0.0/16
# Route specific subnet through this peer
Route = 192.168.1.0/24
```

### Protocol and Port-Based Routing

```ini
[Peer]
PublicKey = web_peer_public_key
Endpoint = web-vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
# Route web traffic through this peer
Route = 0.0.0.0/0:tcp:80,443

[Peer]
PublicKey = dev_peer_public_key
Endpoint = dev-vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
# Route development services through this peer
Route = 0.0.0.0/0:tcp:3000-4000
Route = 0.0.0.0/0:tcp:8080-9000
```

### Complex Multi-Peer Setup

```ini
[Interface]
PrivateKey = your_private_key
Address = 10.150.0.2/24

# Peer 1: General purpose VPN
[Peer]
PublicKey = general_vpn_public_key
Endpoint = general-vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
Route = 0.0.0.0/0  # Default route for all traffic

# Peer 2: Corporate network access
[Peer]
PublicKey = corp_vpn_public_key
Endpoint = corp-vpn.example.com:51820
AllowedIPs = 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
# Route corporate networks
Route = 10.0.0.0/8
Route = 172.16.0.0/12
Route = 192.168.0.0/16
# Route specific services
Route = 0.0.0.0/0:tcp:22     # SSH through corporate VPN
Route = 0.0.0.0/0:tcp:3389   # RDP through corporate VPN

# Peer 3: Streaming and gaming
[Peer]
PublicKey = gaming_vpn_public_key
Endpoint = gaming-vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
# Route gaming and streaming ports
Route = 0.0.0.0/0:udp:5000-6000   # Gaming ports
Route = 0.0.0.0/0:tcp:1935        # RTMP streaming
```

## Routing Priority

1. **Most specific CIDR wins**: `/32` routes take precedence over `/24`, which take precedence over `/0`
2. **Order matters**: For same CIDR specificity, routes listed first have higher priority
3. **Protocol matching**: Protocol-specific routes only match their protocol
4. **Port matching**: Port-specific routes only match connections to those ports

## How It Works

1. When a connection is initiated, WrapGuard checks the destination IP, protocol, and port
2. It searches through all configured routing policies to find the best match
3. Traffic is routed through the WireGuard peer with the matching policy
4. If no policy matches, it falls back to checking AllowedIPs
5. If still no match, the default peer (first one with `0.0.0.0/0`) is used

## Testing Your Configuration

To test your routing configuration:

```bash
# Check which peer would handle specific traffic
wrapguard --config=policy-routing.conf -- curl https://example.com
wrapguard --config=policy-routing.conf -- ssh user@192.168.1.100
wrapguard --config=policy-routing.conf -- nc -v 10.0.0.5 3000
```

Enable debug logging to see routing decisions:

```bash
wrapguard --config=policy-routing.conf --log-level=debug -- your_command
```

## Limitations

- Currently only supports IPv4 routing
- Maximum of one route per line (no comma-separated CIDRs)
- Port ranges in route specifications don't support comma-separated values