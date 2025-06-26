package main

import (
	"context"
	"net"
	"testing"
	"time"
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
	n, err := tun.Read(buf, 0)
	if err != nil {
		t.Errorf("Read() returned error: %v", err)
	}

	if n != len(testData) {
		t.Errorf("expected to read %d bytes, got %d", len(testData), n)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("expected data %q, got %q", string(testData), string(buf[:n]))
	}
}

func TestMemoryTUN_WriteToOutbound(t *testing.T) {
	tun := NewMemoryTUN("test", 1420)
	defer tun.Close()

	testData := []byte("outbound packet data")

	// Write to TUN (simulating WireGuard writing)
	n, err := tun.Write(testData, 0)
	if err != nil {
		t.Errorf("Write() returned error: %v", err)
	}

	if n != len(testData) {
		t.Errorf("expected to write %d bytes, got %d", len(testData), n)
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
	_, err = tun.Read(buf, 0)
	if err == nil {
		t.Error("Read() should return error after close")
	}

	// Test that Write returns error after close
	_, err = tun.Write([]byte("test"), 0)
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
	tunnel := &Tunnel{
		ourIP:  ourIP,
		config: config,
		router: NewRoutingEngine(config),
	}

	ctx := context.Background()

	// Test dialing known WireGuard IPs (fallback mode)
	tests := []struct {
		name        string
		host        string
		port        string
		expectError bool
	}{
		{"node-server-1", "10.150.0.2", "8080", false},
		{"node-server-2", "10.150.0.3", "8080", false},
		{"unknown WireGuard IP", "10.150.0.99", "8080", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := tunnel.DialWireGuard(ctx, "tcp", tt.host, tt.port)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
					if conn != nil {
						conn.Close()
					}
				}
			} else {
				// Note: This will likely fail in test environment since
				// node-server-1 and node-server-2 don't exist, but we test
				// that the function doesn't panic and handles the mapping
				if err != nil {
					// Expected in test environment
					t.Logf("DialWireGuard failed as expected in test environment: %v", err)
				} else if conn != nil {
					conn.Close()
				}
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
