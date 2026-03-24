package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Tunnel struct {
	device   *device.Device
	tun      tun.Device
	ourIP    netip.Addr
	connMap  map[string]*TunnelConn
	mutex    sync.RWMutex
	router   *RoutingEngine   // Add routing engine
	config   *WireGuardConfig // Keep config reference
	dialFn   func(ctx context.Context, network, address string) (net.Conn, error)
	listenFn func(*net.TCPAddr) (net.Listener, error)
}

type TunnelConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	readChan   chan []byte
	writeChan  chan []byte
	closed     bool
	mutex      sync.RWMutex
}

// MemoryTUN implements tun.Device for userspace packet handling
type MemoryTUN struct {
	inbound  chan []byte
	outbound chan []byte
	mtu      int
	name     string
	events   chan tun.Event
	closed   bool
	mutex    sync.RWMutex
	tunnel   *Tunnel
}

func NewMemoryTUN(name string, mtu int) *MemoryTUN {
	return &MemoryTUN{
		inbound:  make(chan []byte, 100),
		outbound: make(chan []byte, 100),
		mtu:      mtu,
		name:     name,
		events:   make(chan tun.Event, 10),
	}
}

func (m *MemoryTUN) File() *os.File { return nil }

func (m *MemoryTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	packet, ok := <-m.inbound
	if !ok {
		return 0, fmt.Errorf("TUN closed")
	}

	// Read a single packet into the first buffer
	if len(bufs) > 0 {
		n := copy(bufs[0][offset:], packet)
		sizes[0] = n
		return 1, nil
	}
	return 0, nil
}

func (m *MemoryTUN) Write(bufs [][]byte, offset int) (int, error) {
	m.mutex.RLock()
	if m.closed {
		m.mutex.RUnlock()
		return 0, fmt.Errorf("TUN closed")
	}
	m.mutex.RUnlock()

	// Write all packets in the batch
	written := 0
	for _, buf := range bufs {
		packet := make([]byte, len(buf)-offset)
		copy(packet, buf[offset:])

		// Handle incoming packets from WireGuard
		if m.tunnel != nil {
			go m.tunnel.handleIncomingPacket(packet)
		}

		select {
		case m.outbound <- packet:
			written++
		default:
			// Drop if full
			break
		}
	}

	return written, nil
}

func (m *MemoryTUN) Flush() error             { return nil }
func (m *MemoryTUN) MTU() (int, error)        { return m.mtu, nil }
func (m *MemoryTUN) Name() (string, error)    { return m.name, nil }
func (m *MemoryTUN) Events() <-chan tun.Event { return m.events }
func (m *MemoryTUN) BatchSize() int           { return 1 }

func (m *MemoryTUN) Close() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.closed {
		m.closed = true
		close(m.inbound)
		close(m.outbound)
		close(m.events)
	}
	return nil
}

func NewTunnel(ctx context.Context, config *WireGuardConfig) (*Tunnel, error) {
	_ = ctx

	// Get our WireGuard IP
	ourIP, err := config.GetInterfaceIP()
	if err != nil {
		return nil, fmt.Errorf("failed to parse interface IP: %w", err)
	}

	dnsServers, err := parseDNSAddrs(config.Interface.DNS)
	if err != nil {
		return nil, fmt.Errorf("failed to parse interface DNS servers: %w", err)
	}

	tunDevice, tnet, err := netstack.CreateNetTUN([]netip.Addr{ourIP}, dnsServers, 1420)
	if err != nil {
		return nil, fmt.Errorf("failed to create userspace netstack tunnel: %w", err)
	}

	tunnel := &Tunnel{
		tun:     tunDevice,
		ourIP:   ourIP,
		connMap: make(map[string]*TunnelConn),
		config:  config,
		router:  NewRoutingEngine(config),
		dialFn:  tnet.DialContext,
		listenFn: func(addr *net.TCPAddr) (net.Listener, error) {
			return tnet.ListenTCP(addr)
		},
	}

	// Create WireGuard device
	logger := device.NewLogger(
		device.LogLevelSilent,
		fmt.Sprintf("[%s] ", "wg"),
	)

	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)

	// Configure device
	if err := configureDevice(dev, config); err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to configure device: %w", err)
	}

	// Bring device up
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to bring device up: %w", err)
	}

	tunnel.device = dev
	return tunnel, nil
}

func configureDevice(dev *device.Device, config *WireGuardConfig) error {
	ipcConfig := fmt.Sprintf("private_key=%s\n", config.Interface.PrivateKey)

	if config.Interface.ListenPort > 0 {
		ipcConfig += fmt.Sprintf("listen_port=%d\n", config.Interface.ListenPort)
	}

	for _, peer := range config.Peers {
		ipcConfig += fmt.Sprintf("public_key=%s\n", peer.PublicKey)

		if peer.PresharedKey != "" {
			ipcConfig += fmt.Sprintf("preshared_key=%s\n", peer.PresharedKey)
		}

		if peer.Endpoint != "" {
			ipcConfig += fmt.Sprintf("endpoint=%s\n", peer.Endpoint)
		}

		if peer.PersistentKeepalive > 0 {
			ipcConfig += fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
		}

		for _, allowedIP := range peer.AllowedIPs {
			ipcConfig += fmt.Sprintf("allowed_ip=%s\n", allowedIP)
		}
	}

	return dev.IpcSet(ipcConfig)
}

func (t *Tunnel) handleIncomingPacket(packet []byte) {
	if len(packet) < 20 {
		return // Too short for IP header
	}

	// Parse IP header to extract source/dest
	version := packet[0] >> 4
	if version != 4 {
		return // Only IPv4 for now
	}

	protocol := packet[9]
	if protocol != 6 {
		return // Only TCP for now
	}

	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	// Extract TCP ports
	if len(packet) < 24 {
		return
	}

	srcPort := binary.BigEndian.Uint16(packet[20:22])
	dstPort := binary.BigEndian.Uint16(packet[22:24])

	connKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)

	t.mutex.RLock()
	conn, exists := t.connMap[connKey]
	t.mutex.RUnlock()

	if exists {
		// Deliver to existing connection
		select {
		case conn.readChan <- packet[20:]: // TCP payload
		default:
			// Drop if full
		}
	}
}

// DialContext creates a connection through WireGuard
func (t *Tunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if t.dialFn == nil {
		return nil, fmt.Errorf("WireGuard tunnel dialer is not initialized")
	}
	return t.dialFn(ctx, network, address)
}

func (t *Tunnel) createTCPSyn(dstIP net.IP, dstPort int) []byte {
	// Create a minimal TCP SYN packet
	// This is very simplified - a real implementation would need proper TCP handling
	packet := make([]byte, 40) // IP header (20) + TCP header (20)

	// IP header
	packet[0] = 0x45                                // Version 4, header length 5
	packet[1] = 0x00                                // DSCP/ECN
	binary.BigEndian.PutUint16(packet[2:4], 40)     // Total length
	binary.BigEndian.PutUint16(packet[4:6], 0x1234) // ID
	binary.BigEndian.PutUint16(packet[6:8], 0x4000) // Flags
	packet[8] = 64                                  // TTL
	packet[9] = 6                                   // Protocol (TCP)
	copy(packet[12:16], t.ourIP.AsSlice())          // Source IP
	copy(packet[16:20], dstIP.To4())                // Dest IP

	// TCP header
	binary.BigEndian.PutUint16(packet[20:22], 12345)           // Source port
	binary.BigEndian.PutUint16(packet[22:24], uint16(dstPort)) // Dest port
	binary.BigEndian.PutUint32(packet[24:28], 0x12345678)      // Seq number
	binary.BigEndian.PutUint32(packet[28:32], 0)               // Ack number
	packet[32] = 0x50                                          // Header length
	packet[33] = 0x02                                          // SYN flag
	binary.BigEndian.PutUint16(packet[34:36], 8192)            // Window

	return packet
}

func (t *Tunnel) Listen(network, address string) (net.Listener, error) {
	if t.listenFn == nil {
		return nil, fmt.Errorf("WireGuard tunnel listener is not initialized")
	}

	switch normalizeNetworkProtocol(network) {
	case "tcp":
	default:
		return nil, fmt.Errorf("unsupported listen network %q", network)
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve listen address %q: %w", address, err)
	}

	return t.listenFn(tcpAddr)
}

// IsWireGuardIP checks if an IP is in the WireGuard network
func (t *Tunnel) IsWireGuardIP(ip net.IP) bool {
	// Check if the IP is in the 10.150.0.0/24 range (our WireGuard network)
	_, wgNet, err := net.ParseCIDR("10.150.0.0/24")
	if err != nil {
		return false
	}
	return wgNet.Contains(ip)
}

// DialWireGuard creates a connection to a WireGuard IP through the tunnel
func (t *Tunnel) DialWireGuard(ctx context.Context, network, host, port string) (net.Conn, error) {
	// Parse destination IP and port
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", host)
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %s", port)
	}

	// Find the appropriate peer using routing engine
	peer, peerIdx := t.router.FindPeerForDestination(ip, portNum, normalizeNetworkProtocol(network))
	if peer == nil {
		return nil, fmt.Errorf("no route to %s:%s", host, port)
	}

	logger.Debugf("WireGuard tunnel: routing %s:%s through peer %d (endpoint: %s)", host, port, peerIdx, peer.Endpoint)
	if t.dialFn == nil {
		return nil, fmt.Errorf("WireGuard tunnel dialer is not initialized")
	}

	address := net.JoinHostPort(host, port)
	return t.dialFn(ctx, network, address)
}

func (t *Tunnel) Close() error {
	if t.device != nil {
		t.device.Close()
		t.device = nil
		t.tun = nil
	}
	if t.tun != nil {
		t.tun.Close()
		t.tun = nil
	}
	return nil
}

// TunnelConn implements net.Conn
func (tc *TunnelConn) Read(b []byte) (int, error) {
	data, ok := <-tc.readChan
	if !ok {
		return 0, fmt.Errorf("connection closed")
	}
	copy(b, data)
	return len(data), nil
}

func (tc *TunnelConn) Write(b []byte) (int, error) {
	select {
	case tc.writeChan <- b:
		return len(b), nil
	default:
		return 0, fmt.Errorf("write buffer full")
	}
}

func (tc *TunnelConn) Close() error {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	if !tc.closed {
		tc.closed = true
		close(tc.readChan)
		close(tc.writeChan)
	}
	return nil
}

func (tc *TunnelConn) LocalAddr() net.Addr                { return tc.localAddr }
func (tc *TunnelConn) RemoteAddr() net.Addr               { return tc.remoteAddr }
func (tc *TunnelConn) SetDeadline(t time.Time) error      { return nil }
func (tc *TunnelConn) SetReadDeadline(t time.Time) error  { return nil }
func (tc *TunnelConn) SetWriteDeadline(t time.Time) error { return nil }

func mustParsePort(s string) int {
	p, _ := strconv.Atoi(s)
	return p
}

func normalizeNetworkProtocol(network string) string {
	switch {
	case strings.HasPrefix(network, "tcp"):
		return "tcp"
	case strings.HasPrefix(network, "udp"):
		return "udp"
	default:
		return network
	}
}

func parseDNSAddrs(entries []string) ([]netip.Addr, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	addrs := make([]netip.Addr, 0, len(entries))
	for _, entry := range entries {
		addr, err := netip.ParseAddr(strings.TrimSpace(entry))
		if err != nil {
			return nil, fmt.Errorf("invalid DNS address %q: %w", entry, err)
		}
		addrs = append(addrs, addr)
	}

	return addrs, nil
}
