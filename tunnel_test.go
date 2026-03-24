package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func TestNewMemoryTUN(t *testing.T) {
	tun := NewMemoryTUN("test-tun", 1420)

	if tun == nil {
		t.Fatal("NewMemoryTUN returned nil")
	}

	if tun.mtu != 1420 {
		t.Errorf("expected MTU 1420, got %d", tun.mtu)
	}

	if tun.name != "test-tun" {
		t.Errorf("expected name 'test-tun', got %q", tun.name)
	}

	if tun.closed {
		t.Error("TUN should not be closed initially")
	}

	if tun.inbound == nil {
		t.Error("inbound channel not initialized")
	}

	if tun.outbound == nil {
		t.Error("outbound channel not initialized")
	}

	if tun.events == nil {
		t.Error("events channel not initialized")
	}

	tun.Close()
}

func TestMemoryTUN_File(t *testing.T) {
	tun := NewMemoryTUN("test", 1420)
	defer tun.Close()

	if file := tun.File(); file != nil {
		t.Error("File() should return nil for memory TUN")
	}
}

func TestMemoryTUN_MTU(t *testing.T) {
	tun := NewMemoryTUN("test", 1500)
	defer tun.Close()

	mtu, err := tun.MTU()
	if err != nil {
		t.Errorf("MTU() returned error: %v", err)
	}

	if mtu != 1500 {
		t.Errorf("expected MTU 1500, got %d", mtu)
	}
}

func TestMemoryTUN_Name(t *testing.T) {
	tun := NewMemoryTUN("test-interface", 1420)
	defer tun.Close()

	name, err := tun.Name()
	if err != nil {
		t.Errorf("Name() returned error: %v", err)
	}

	if name != "test-interface" {
		t.Errorf("expected name 'test-interface', got %q", name)
	}
}

func TestMemoryTUN_Events(t *testing.T) {
	tun := NewMemoryTUN("test", 1420)
	defer tun.Close()

	events := tun.Events()
	if events == nil {
		t.Error("Events() returned nil channel")
	}
}

func TestMemoryTUN_ReadWrite(t *testing.T) {
	tun := NewMemoryTUN("test", 1420)
	defer tun.Close()

	// Test data
	testData := []byte("test packet data")

	// Write data
	go func() {
		time.Sleep(10 * time.Millisecond) // Small delay to ensure Read is waiting
		tun.inbound <- testData
	}()

	// Read data
	buf := make([]byte, 1500)
	bufs := [][]byte{buf}
	sizes := make([]int, 1)
	n, err := tun.Read(bufs, sizes, 0)
	if err != nil {
		t.Errorf("Read() returned error: %v", err)
	}

	if n != 1 {
		t.Errorf("expected to read 1 packet, got %d", n)
	}

	if sizes[0] != len(testData) {
		t.Errorf("expected packet size %d bytes, got %d", len(testData), sizes[0])
	}

	if string(buf[:sizes[0]]) != string(testData) {
		t.Errorf("expected data %q, got %q", string(testData), string(buf[:sizes[0]]))
	}
}

func TestMemoryTUN_WriteToOutbound(t *testing.T) {
	tun := NewMemoryTUN("test", 1420)
	defer tun.Close()

	testData := []byte("outbound packet data")

	// Write to TUN (simulating WireGuard writing)
	bufs := [][]byte{testData}
	n, err := tun.Write(bufs, 0)
	if err != nil {
		t.Errorf("Write() returned error: %v", err)
	}

	if n != 1 {
		t.Errorf("expected to write 1 packet, got %d", n)
	}

	// Check if data appeared in outbound channel
	select {
	case data := <-tun.outbound:
		if string(data) != string(testData) {
			t.Errorf("expected outbound data %q, got %q", string(testData), string(data))
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("no data received on outbound channel")
	}
}

func TestMemoryTUN_Close(t *testing.T) {
	tun := NewMemoryTUN("test", 1420)

	// Close the TUN
	err := tun.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	if !tun.closed {
		t.Error("TUN should be marked as closed")
	}

	// Test that Read returns error after close
	buf := make([]byte, 100)
	bufs := [][]byte{buf}
	sizes := make([]int, 1)
	_, err = tun.Read(bufs, sizes, 0)
	if err == nil {
		t.Error("Read() should return error after close")
	}

	// Test that Write returns error after close
	_, err = tun.Write([][]byte{[]byte("test")}, 0)
	if err == nil {
		t.Error("Write() should return error after close")
	}

	// Multiple closes should not panic
	err = tun.Close()
	if err != nil {
		t.Errorf("Second Close() returned error: %v", err)
	}
}

func TestMemoryTUN_Flush(t *testing.T) {
	tun := NewMemoryTUN("test", 1420)
	defer tun.Close()

	// Flush should not return error
	err := tun.Flush()
	if err != nil {
		t.Errorf("Flush() returned error: %v", err)
	}
}

func TestTunnel_IsWireGuardIP(t *testing.T) {
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			Address: "10.150.0.2/24",
		},
	}

	ourIP, _ := config.GetInterfaceIP()
	tunnel := &Tunnel{
		ourIP: ourIP,
	}

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"WireGuard network IP", "10.150.0.5", true},
		{"Our IP", "10.150.0.2", true},
		{"Network address", "10.150.0.0", true},
		{"Broadcast address", "10.150.0.255", true},
		{"Outside network", "10.151.0.5", false},
		{"Different network", "192.168.1.1", false},
		{"Public IP", "8.8.8.8", false},
		{"Invalid IP", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := tunnel.IsWireGuardIP(ip)

			if result != tt.expected {
				t.Errorf("IsWireGuardIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestTunnel_DialWireGuard(t *testing.T) {
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			Address: "10.150.0.2/24",
		},
		Peers: []PeerConfig{
			{
				PublicKey:  "test-peer",
				Endpoint:   "test.example.com:51820",
				AllowedIPs: []string{"0.0.0.0/0"},
			},
		},
	}

	ourIP, _ := config.GetInterfaceIP()
	var (
		gotNetwork string
		gotAddress string
	)
	tunnel := &Tunnel{
		ourIP:  ourIP,
		config: config,
		router: NewRoutingEngine(config),
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			gotNetwork = network
			gotAddress = address
			return nil, fmt.Errorf("dial blocked in test")
		},
	}

	tests := []struct {
		name        string
		host        string
		port        string
		network     string
		expectError bool
		wantAddress string
	}{
		{"default-route target", "104.16.185.241", "443", "tcp", false, "104.16.185.241:443"},
		{"overlay target", "10.150.0.3", "8080", "tcp4", false, "10.150.0.3:8080"},
		{"no route", "2001:4860:4860::8888", "53", "udp6", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNetwork = ""
			gotAddress = ""

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			conn, err := tunnel.DialWireGuard(ctx, tt.network, tt.host, tt.port)

			if tt.expectError {
				if err == nil || err.Error() != fmt.Sprintf("no route to %s:%s", tt.host, tt.port) {
					t.Fatalf("expected no-route error, got conn=%v err=%v", conn, err)
				}
				if gotAddress != "" || gotNetwork != "" {
					t.Fatalf("dialer should not have been invoked on no-route, got network=%q address=%q", gotNetwork, gotAddress)
				}
				return
			}

			if err == nil || err.Error() != "dial blocked in test" {
				t.Fatalf("expected test dialer error, got conn=%v err=%v", conn, err)
			}
			if gotNetwork != tt.network {
				t.Fatalf("dial network = %q, want %q", gotNetwork, tt.network)
			}
			if gotAddress != tt.wantAddress {
				t.Fatalf("dial address = %q, want %q", gotAddress, tt.wantAddress)
			}
			if conn != nil {
				conn.Close()
			}
		})
	}
}

func TestTunnel_DialContext(t *testing.T) {
	tunnel := &Tunnel{
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "203.0.113.10:443" {
				t.Fatalf("unexpected dial args: network=%q address=%q", network, address)
			}
			return nil, fmt.Errorf("dial blocked in test")
		},
	}

	_, err := tunnel.DialContext(context.Background(), "tcp", "203.0.113.10:443")
	if err == nil || err.Error() != "dial blocked in test" {
		t.Fatalf("expected injected dialer error, got %v", err)
	}
}

func TestTunnel_DialContextRequiresDialer(t *testing.T) {
	_, err := (&Tunnel{}).DialContext(context.Background(), "tcp", "203.0.113.10:443")
	if err == nil || err.Error() != "WireGuard tunnel dialer is not initialized" {
		t.Fatalf("expected missing dialer error, got %v", err)
	}
}

func TestTunnel_Listen(t *testing.T) {
	tunnel := &Tunnel{
		listenFn: func(addr *net.TCPAddr) (net.Listener, error) {
			if addr.Port != 8080 {
				t.Fatalf("unexpected listen port: %d", addr.Port)
			}
			return nil, fmt.Errorf("listen blocked in test")
		},
	}

	_, err := tunnel.Listen("tcp", ":8080")
	if err == nil || err.Error() != "listen blocked in test" {
		t.Fatalf("expected injected listen error, got %v", err)
	}
}

func TestTunnel_ListenRejectsInvalidAddress(t *testing.T) {
	tunnel := &Tunnel{
		listenFn: func(addr *net.TCPAddr) (net.Listener, error) {
			t.Fatal("listenFn should not be called when address resolution fails")
			return nil, nil
		},
	}

	_, err := tunnel.Listen("tcp", "not-a-valid-listen-address")
	if err == nil || !strings.Contains(err.Error(), "failed to resolve listen address") {
		t.Fatalf("expected listen address resolution error, got %v", err)
	}
}

func TestTunnel_ListenRejectsUnsupportedNetwork(t *testing.T) {
	tunnel := &Tunnel{}

	_, err := tunnel.Listen("udp", ":8080")
	if err == nil || err.Error() != `WireGuard tunnel listener is not initialized` {
		t.Fatalf("expected uninitialized listener error, got %v", err)
	}
}

func TestTunnel_DialWireGuardRejectsInvalidInputs(t *testing.T) {
	tunnel := &Tunnel{
		router: NewRoutingEngine(&WireGuardConfig{
			Peers: []PeerConfig{
				{
					AllowedIPs: []string{"0.0.0.0/0"},
				},
			},
		}),
	}

	tests := []struct {
		name    string
		host    string
		port    string
		wantErr string
	}{
		{name: "invalid-host", host: "example.com", port: "443", wantErr: "invalid IP address: example.com"},
		{name: "invalid-port", host: "203.0.113.10", port: "not-a-port", wantErr: "invalid port: not-a-port"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tunnel.DialWireGuard(context.Background(), "tcp", tt.host, tt.port)
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("expected %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestCreateTCPSyn(t *testing.T) {
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			Address: "10.150.0.2/24",
		},
	}

	ourIP, _ := config.GetInterfaceIP()
	tunnel := &Tunnel{
		ourIP: ourIP,
	}

	dstIP := net.ParseIP("10.150.0.3")
	dstPort := 80

	packet := tunnel.createTCPSyn(dstIP, dstPort)

	if len(packet) != 40 {
		t.Errorf("expected packet length 40, got %d", len(packet))
	}

	// Check IP version
	version := packet[0] >> 4
	if version != 4 {
		t.Errorf("expected IP version 4, got %d", version)
	}

	// Check protocol (should be TCP = 6)
	protocol := packet[9]
	if protocol != 6 {
		t.Errorf("expected protocol 6 (TCP), got %d", protocol)
	}

	// Check source IP
	srcIP := net.IP(packet[12:16])
	if !srcIP.Equal(ourIP.AsSlice()) {
		t.Errorf("expected source IP %v, got %v", ourIP, srcIP)
	}

	// Check destination IP
	dstIPFromPacket := net.IP(packet[16:20])
	if !dstIPFromPacket.Equal(dstIP) {
		t.Errorf("expected destination IP %v, got %v", dstIP, dstIPFromPacket)
	}
}

func TestTunnel_HandleIncomingPacket(t *testing.T) {
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			Address: "10.150.0.2/24",
		},
	}

	ourIP, _ := config.GetInterfaceIP()
	tunnel := &Tunnel{
		ourIP:   ourIP,
		connMap: make(map[string]*TunnelConn),
	}

	// Test with short packet
	tunnel.handleIncomingPacket([]byte("short"))
	// Should not panic

	// Test with non-IPv4 packet
	packet := make([]byte, 40)
	packet[0] = 0x60 // IPv6
	tunnel.handleIncomingPacket(packet)
	// Should not panic

	// Test with non-TCP packet
	packet[0] = 0x45 // IPv4
	packet[9] = 17   // UDP
	tunnel.handleIncomingPacket(packet)
	// Should not panic

	// Test with too short for TCP
	packet[9] = 6 // TCP
	shortPacket := packet[:23]
	tunnel.handleIncomingPacket(shortPacket)
	// Should not panic
}

func TestTunnelConn_Implementation(t *testing.T) {
	readChan := make(chan []byte, 10)
	writeChan := make(chan []byte, 10)

	localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	conn := &TunnelConn{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		readChan:   readChan,
		writeChan:  writeChan,
	}

	// Test addresses
	if conn.LocalAddr() != localAddr {
		t.Errorf("LocalAddr() = %v, want %v", conn.LocalAddr(), localAddr)
	}

	if conn.RemoteAddr() != remoteAddr {
		t.Errorf("RemoteAddr() = %v, want %v", conn.RemoteAddr(), remoteAddr)
	}

	// Test Write
	testData := []byte("test data")
	n, err := conn.Write(testData)
	if err != nil {
		t.Errorf("Write() returned error: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write() returned %d, want %d", n, len(testData))
	}

	// Check data was written to channel
	select {
	case data := <-writeChan:
		if string(data) != string(testData) {
			t.Errorf("written data = %q, want %q", string(data), string(testData))
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("no data written to channel")
	}

	// Test Read
	readData := []byte("read test data")
	readChan <- readData

	buf := make([]byte, 100)
	n, err = conn.Read(buf)
	if err != nil {
		t.Errorf("Read() returned error: %v", err)
	}
	if n != len(readData) {
		t.Errorf("Read() returned %d bytes, want %d", n, len(readData))
	}
	if string(buf[:n]) != string(readData) {
		t.Errorf("read data = %q, want %q", string(buf[:n]), string(readData))
	}

	// Test deadline methods (should not return error)
	if err := conn.SetDeadline(time.Now()); err != nil {
		t.Errorf("SetDeadline() returned error: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now()); err != nil {
		t.Errorf("SetReadDeadline() returned error: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Now()); err != nil {
		t.Errorf("SetWriteDeadline() returned error: %v", err)
	}

	// Test Close
	err = conn.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	if !conn.closed {
		t.Error("connection should be marked as closed")
	}

	// Test Read after close
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("Read() should return error after close")
	}

	// Multiple closes should not panic
	err = conn.Close()
	if err != nil {
		t.Errorf("second Close() returned error: %v", err)
	}
}

func TestTunnelConn_WriteBufferFull(t *testing.T) {
	// Create connection with small buffer
	writeChan := make(chan []byte, 1)

	conn := &TunnelConn{
		writeChan: writeChan,
	}

	// Fill the buffer
	_, err := conn.Write([]byte("first"))
	if err != nil {
		t.Errorf("first Write() returned error: %v", err)
	}

	// Second write should fail due to full buffer
	_, err = conn.Write([]byte("second"))
	if err == nil {
		t.Error("Write() should return error when buffer is full")
	}
}

func TestMustParsePort(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"80", 80},
		{"8080", 8080},
		{"443", 443},
		{"0", 0},
		{"invalid", 0}, // strconv.Atoi returns 0 for invalid input
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := mustParsePort(tt.input)
			if result != tt.expected {
				t.Errorf("mustParsePort(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

// Integration test for tunnel creation (may fail due to WireGuard dependencies)
func TestNewTunnel_Integration(t *testing.T) {
	// This test may fail in CI/test environments without proper WireGuard setup
	// but tests the tunnel creation logic

	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			PrivateKey: "cGluZy1wcml2YXRlLWtleS0xMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=", // base64 encoded 32 bytes
			Address:    "10.150.0.2/24",
		},
		Peers: []PeerConfig{
			{
				PublicKey:  "cGluZy1wdWJsaWMta2V5LTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy", // base64 encoded 32 bytes
				Endpoint:   "127.0.0.1:51820",
				AllowedIPs: []string{"0.0.0.0/0"},
			},
		},
	}

	ctx := context.Background()
	tunnel, err := NewTunnel(ctx, config)

	// In test environment, this will likely fail due to missing WireGuard setup
	// but we test that it doesn't panic and handles errors gracefully
	if err != nil {
		t.Logf("NewTunnel failed as expected in test environment: %v", err)
		return
	}

	if tunnel == nil {
		t.Error("NewTunnel returned nil tunnel without error")
		return
	}

	// Test tunnel properties
	expectedIP, _ := config.GetInterfaceIP()
	if tunnel.ourIP != expectedIP {
		t.Errorf("tunnel.ourIP = %v, want %v", tunnel.ourIP, expectedIP)
	}

	if tunnel.device == nil {
		t.Error("tunnel.device is nil")
	}

	if tunnel.tun == nil {
		t.Error("tunnel.tun is nil")
	}

	if tunnel.connMap == nil {
		t.Error("tunnel.connMap is nil")
	}

	// Clean up
	tunnel.Close()
}

// Test tunnel close
func TestTunnel_Close(t *testing.T) {
	tun := NewMemoryTUN("test", 1420)
	tunnel := &Tunnel{
		tun: tun,
		// device: nil, // Don't create actual WireGuard device in test
	}

	err := tunnel.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// TUN should be closed
	if !tun.closed {
		t.Error("TUN should be closed after tunnel close")
	}
}

func TestTunnel_EndToEndTCPAcrossWireGuard(t *testing.T) {
	serverPriv, serverPub := mustGenerateWireGuardKeyPair(t)
	clientPriv, clientPub := mustGenerateWireGuardKeyPair(t)

	serverUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve server UDP port: %v", err)
	}
	serverPort := serverUDP.LocalAddr().(*net.UDPAddr).Port
	_ = serverUDP.Close()

	serverConfig := &WireGuardConfig{
		Interface: InterfaceConfig{
			PrivateKey: serverPriv,
			Address:    "10.150.0.1/24",
			ListenPort: serverPort,
		},
		Peers: []PeerConfig{
			{
				PublicKey:  clientPub,
				AllowedIPs: []string{"10.150.0.2/32"},
			},
		},
	}

	clientConfig := &WireGuardConfig{
		Interface: InterfaceConfig{
			PrivateKey: clientPriv,
			Address:    "10.150.0.2/24",
		},
		Peers: []PeerConfig{
			{
				PublicKey:           serverPub,
				Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
				AllowedIPs:          []string{"10.150.0.0/24"},
				PersistentKeepalive: 1,
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverTunnel, err := NewTunnel(ctx, serverConfig)
	if err != nil {
		t.Fatalf("failed to create server tunnel: %v", err)
	}
	defer serverTunnel.Close()

	clientTunnel, err := NewTunnel(ctx, clientConfig)
	if err != nil {
		t.Fatalf("failed to create client tunnel: %v", err)
	}
	defer clientTunnel.Close()

	listener, err := serverTunnel.Listen("tcp", ":8080")
	if err != nil {
		t.Fatalf("failed to listen over server tunnel: %v", err)
	}
	defer listener.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrCh <- fmt.Errorf("accept failed: %w", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 32)
		n, err := conn.Read(buf)
		if err != nil {
			serverErrCh <- fmt.Errorf("server read failed: %w", err)
			return
		}
		if string(buf[:n]) != "ping-over-wrapguard" {
			serverErrCh <- fmt.Errorf("unexpected payload %q", string(buf[:n]))
			return
		}

		if _, err := io.WriteString(conn, "pong-from-peer"); err != nil {
			serverErrCh <- fmt.Errorf("server write failed: %w", err)
			return
		}

		serverErrCh <- nil
	}()

	var clientConn net.Conn
	deadline := time.Now().Add(6 * time.Second)
	for {
		clientConn, err = clientTunnel.DialWireGuard(ctx, "tcp", "10.150.0.1", "8080")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("failed to dial peer over WireGuard: %v", err)
		}
		time.Sleep(150 * time.Millisecond)
	}
	defer clientConn.Close()

	if _, err := io.WriteString(clientConn, "ping-over-wrapguard"); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	reply := make([]byte, 32)
	n, err := clientConn.Read(reply)
	if err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if string(reply[:n]) != "pong-from-peer" {
		t.Fatalf("unexpected reply %q", string(reply[:n]))
	}

	select {
	case err := <-serverErrCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server handler did not complete")
	}
}

func TestNormalizeNetworkProtocol(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "tcp", want: "tcp"},
		{input: "tcp4", want: "tcp"},
		{input: "tcp6", want: "tcp"},
		{input: "udp", want: "udp"},
		{input: "udp6", want: "udp"},
		{input: "ping", want: "ping"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := normalizeNetworkProtocol(tt.input); got != tt.want {
				t.Fatalf("normalizeNetworkProtocol(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTunnelDialWireGuardNormalizesPolicyProtocol(t *testing.T) {
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			Address: "10.150.0.2/24",
		},
		Peers: []PeerConfig{
			{
				PublicKey:  "policy-peer",
				Endpoint:   "policy.example.com:51820",
				AllowedIPs: []string{"10.200.0.0/16"},
				RoutingPolicies: []RoutingPolicy{
					{
						DestinationCIDR: "203.0.113.0/24",
						Protocol:        "tcp",
						PortRange:       PortRange{Start: 443, End: 443},
						Priority:        100,
					},
				},
			},
		},
	}

	var (
		gotNetwork string
		gotAddress string
	)
	tunnel := &Tunnel{
		config: config,
		router: NewRoutingEngine(config),
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			gotNetwork = network
			gotAddress = address
			return nil, fmt.Errorf("dial blocked in test")
		},
	}

	_, err := tunnel.DialWireGuard(context.Background(), "tcp4", "203.0.113.10", "443")
	if err == nil || err.Error() != "dial blocked in test" {
		t.Fatalf("expected test dialer error, got %v", err)
	}
	if gotNetwork != "tcp4" {
		t.Fatalf("dial network = %q, want tcp4", gotNetwork)
	}
	if gotAddress != "203.0.113.10:443" {
		t.Fatalf("dial address = %q, want 203.0.113.10:443", gotAddress)
	}
}

func TestTunnel_DialWireGuardRejectsHostnames(t *testing.T) {
	tunnel := &Tunnel{
		router: NewRoutingEngine(&WireGuardConfig{
			Peers: []PeerConfig{
				{
					AllowedIPs: []string{"0.0.0.0/0"},
				},
			},
		}),
	}

	_, err := tunnel.DialWireGuard(context.Background(), "tcp", "example.com", "443")
	if err == nil || err.Error() != "invalid IP address: example.com" {
		t.Fatalf("expected hostname rejection, got %v", err)
	}
}

func TestParseDNSAddrs(t *testing.T) {
	got, err := parseDNSAddrs([]string{"8.8.8.8", " 2001:4860:4860::8888 "})
	if err != nil {
		t.Fatalf("parseDNSAddrs returned error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 DNS addresses, got %d", len(got))
	}
	if got[0].String() != "8.8.8.8" || got[1].String() != "2001:4860:4860::8888" {
		t.Fatalf("unexpected DNS addresses: %v", got)
	}
}

func TestParseDNSAddrsEmptyInput(t *testing.T) {
	got, err := parseDNSAddrs(nil)
	if err != nil {
		t.Fatalf("parseDNSAddrs returned error for empty input: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil DNS addrs for empty input, got %v", got)
	}
}

func TestParseDNSAddrsInvalid(t *testing.T) {
	if _, err := parseDNSAddrs([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected invalid DNS address error")
	}
}

func mustGenerateWireGuardKeyPair(t *testing.T) (privateHex, publicHex string) {
	t.Helper()

	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64

	publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to derive public key: %v", err)
	}

	return hex.EncodeToString(privateKey[:]), hex.EncodeToString(publicKey)
}
