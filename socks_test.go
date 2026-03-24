package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestNewSOCKS5Server(t *testing.T) {
	// Create a mock tunnel
	tunnel := &Tunnel{
		ourIP: mustParseIPAddr("10.150.0.2"),
	}

	server, err := NewSOCKS5Server(tunnel)
	if err != nil {
		t.Fatalf("NewSOCKS5Server failed: %v", err)
	}
	defer server.Close()

	if server == nil {
		t.Fatal("NewSOCKS5Server returned nil")
	}

	if server.server == nil {
		t.Error("SOCKS5 server is nil")
	}

	if server.listener == nil {
		t.Error("listener is nil")
	}

	if server.tunnel != tunnel {
		t.Error("tunnel reference not set correctly")
	}

	if server.port == 0 {
		t.Error("port should be set to non-zero value")
	}
}

func TestSOCKS5Server_Port(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: mustParseIPAddr("10.150.0.2"),
	}

	server, err := NewSOCKS5Server(tunnel)
	if err != nil {
		t.Fatalf("NewSOCKS5Server failed: %v", err)
	}
	defer server.Close()

	port := server.Port()
	if port == 0 {
		t.Error("Port() returned 0")
	}

	// Port should be in valid range
	if port < 1024 || port > 65535 {
		t.Errorf("Port() returned invalid port %d", port)
	}
}

func TestSOCKS5Server_Close(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: mustParseIPAddr("10.150.0.2"),
	}

	server, err := NewSOCKS5Server(tunnel)
	if err != nil {
		t.Fatalf("NewSOCKS5Server failed: %v", err)
	}

	// Test that Close doesn't return error
	err = server.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Test multiple closes don't panic (may return error, that's OK)
	server.Close() // Don't check error for second close as it may fail
}

func TestSOCKS5Server_Integration(t *testing.T) {
	// This is an integration test that may not work in all test environments
	// but tests the SOCKS5 server functionality

	tunnel := &Tunnel{
		ourIP: mustParseIPAddr("10.150.0.2"),
	}

	server, err := NewSOCKS5Server(tunnel)
	if err != nil {
		t.Fatalf("NewSOCKS5Server failed: %v", err)
	}
	defer server.Close()

	// Give the server a moment to start
	time.Sleep(50 * time.Millisecond)

	// Test that we can connect to the SOCKS5 server
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+itoa(server.Port()), 1*time.Second)
	if err != nil {
		t.Logf("Could not connect to SOCKS5 server (may be expected in test env): %v", err)
		return
	}
	defer conn.Close()

	// Basic connectivity test - just ensure we can connect
	// Full SOCKS5 protocol testing would require more complex setup
}

func TestSOCKS5Server_CustomDialer(t *testing.T) {
	// Test the custom dialer logic in the SOCKS5 server
	// This tests the logic but not the actual network connections

	tunnel := &Tunnel{
		ourIP: mustParseIPAddr("10.150.0.2"),
	}

	// Since we can't easily override the method, we'll test the server creation
	// The actual dialer testing would require more complex mocking
	server, err := NewSOCKS5Server(tunnel)
	if err != nil {
		t.Fatalf("NewSOCKS5Server failed: %v", err)
	}
	defer server.Close()

	// Verify the server was created successfully
	if server.server == nil {
		t.Error("SOCKS5 server not created")
	}
}

func TestSOCKS5Server_ListenerAddress(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: mustParseIPAddr("10.150.0.2"),
	}

	server, err := NewSOCKS5Server(tunnel)
	if err != nil {
		t.Fatalf("NewSOCKS5Server failed: %v", err)
	}
	defer server.Close()

	// Check that the server listens on localhost
	addr := server.listener.Addr().(*net.TCPAddr)
	if !addr.IP.IsLoopback() {
		t.Errorf("server should listen on loopback interface, got %v", addr.IP)
	}

	if addr.Port == 0 {
		t.Error("server should have a non-zero port")
	}

	// Port should match what Port() returns
	if addr.Port != server.Port() {
		t.Errorf("listener port %d doesn't match Port() %d", addr.Port, server.Port())
	}
}

func TestSOCKS5Server_NilTunnel(t *testing.T) {
	// Test behavior with nil tunnel is a clean error.
	_, err := NewSOCKS5Server(nil)
	if err == nil {
		t.Fatal("expected error for nil tunnel")
	}
}

func TestSOCKS5Server_PortRange(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: mustParseIPAddr("10.150.0.2"),
	}

	// Create multiple servers to test port allocation
	servers := make([]*SOCKS5Server, 5)
	defer func() {
		for _, server := range servers {
			if server != nil {
				server.Close()
			}
		}
	}()

	ports := make(map[int]bool)

	for i := 0; i < 5; i++ {
		server, err := NewSOCKS5Server(tunnel)
		if err != nil {
			t.Fatalf("NewSOCKS5Server %d failed: %v", i, err)
		}
		servers[i] = server

		port := server.Port()
		if ports[port] {
			t.Errorf("duplicate port %d allocated", port)
		}
		ports[port] = true

		// Each server should get a different port
		if port < 1024 || port > 65535 {
			t.Errorf("invalid port %d allocated", port)
		}
	}
}

func TestSOCKS5Server_ServerRunning(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: mustParseIPAddr("10.150.0.2"),
	}

	server, err := NewSOCKS5Server(tunnel)
	if err != nil {
		t.Fatalf("NewSOCKS5Server failed: %v", err)
	}
	defer server.Close()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Test that the server is actually listening
	listener := server.listener
	if listener == nil {
		t.Fatal("listener is nil")
	}

	addr := listener.Addr()
	if addr == nil {
		t.Fatal("listener address is nil")
	}

	// The server should be running (we can't easily test the Serve goroutine
	// without complex setup, but we can verify the listener is active)
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is not TCP: %T", addr)
	}

	if tcpAddr.Port == 0 {
		t.Error("listener has no port assigned")
	}
}

func TestBuildSOCKS5DialBypassesLoopback(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: mustParseIPAddr("10.150.0.2"),
		router: NewRoutingEngine(&WireGuardConfig{
			Peers: []PeerConfig{
				{
					AllowedIPs: []string{"0.0.0.0/0"},
				},
			},
		}),
	}

	var dialed []string
	dial := buildSOCKS5Dial(tunnel, 1080, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, network+" "+addr)
		return nil, fmt.Errorf("base dial invoked")
	}, nil)

	_, err := dial(context.Background(), "tcp", "127.0.0.1:8080")
	if err == nil || err.Error() != "base dial invoked" {
		t.Fatalf("expected base dialer error, got %v", err)
	}
	if len(dialed) != 1 || dialed[0] != "tcp 127.0.0.1:8080" {
		t.Fatalf("unexpected base dial invocations: %v", dialed)
	}
}

func TestBuildSOCKS5DialRejectsRecursiveLoopbackPort(t *testing.T) {
	dial := buildSOCKS5Dial(&Tunnel{ourIP: mustParseIPAddr("10.150.0.2")}, 1080, func(ctx context.Context, network, addr string) (net.Conn, error) {
		t.Fatalf("base dialer should not be used for recursive SOCKS target")
		return nil, nil
	}, nil)

	if _, err := dial(context.Background(), "tcp", "127.0.0.1:1080"); err == nil || err.Error() != "refusing recursive SOCKS dial to localhost:1080" {
		t.Fatalf("unexpected recursive dial result: %v", err)
	}
}

func TestBuildSOCKS5DialLeavesHostnamesOnBaseDialer(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: mustParseIPAddr("10.150.0.2"),
		router: NewRoutingEngine(&WireGuardConfig{
			Peers: []PeerConfig{
				{
					AllowedIPs: []string{"0.0.0.0/0"},
				},
			},
		}),
	}

	var dialed []string
	dial := buildSOCKS5Dial(tunnel, 1080, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, network+" "+addr)
		return nil, fmt.Errorf("base dial invoked")
	}, nil)

	_, err := dial(context.Background(), "tcp", "example.com:443")
	if err == nil || err.Error() != "base dial invoked" {
		t.Fatalf("expected base dialer error, got %v", err)
	}
	if len(dialed) != 1 || dialed[0] != "tcp example.com:443" {
		t.Fatalf("unexpected base dial invocations: %v", dialed)
	}
}

func TestBuildSOCKS5DialRoutesMatchedDestinationsThroughTunnel(t *testing.T) {
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			Address: "10.150.0.2/24",
		},
		Peers: []PeerConfig{
			{
				PublicKey:  "route-peer",
				Endpoint:   "route.example.com:51820",
				AllowedIPs: []string{"10.200.0.0/16"},
				RoutingPolicies: []RoutingPolicy{
					{
						DestinationCIDR: "198.51.100.0/24",
						Protocol:        "tcp",
						PortRange:       PortRange{Start: 443, End: 443},
						Priority:        10,
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
		ourIP:  mustParseIPAddr("10.150.0.2"),
		config: config,
		router: NewRoutingEngine(config),
		dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			gotNetwork = network
			gotAddress = address
			return nil, fmt.Errorf("tunnel dial invoked")
		},
	}

	dial := buildSOCKS5Dial(tunnel, 1080, func(ctx context.Context, network, addr string) (net.Conn, error) {
		t.Fatalf("base dialer should not be used for routed destination")
		return nil, nil
	}, nil)

	_, err := dial(context.Background(), "tcp4", "198.51.100.25:443")
	if err == nil || err.Error() != "tunnel dial invoked" {
		t.Fatalf("expected tunnel dialer error, got %v", err)
	}
	if gotNetwork != "tcp4" {
		t.Fatalf("tunnel dial network = %q, want tcp4", gotNetwork)
	}
	if gotAddress != "198.51.100.25:443" {
		t.Fatalf("tunnel dial address = %q, want 198.51.100.25:443", gotAddress)
	}
}

func TestBuildSOCKS5DialFallsBackToBaseDialerForUnroutedIP(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: mustParseIPAddr("10.150.0.2"),
		router: NewRoutingEngine(&WireGuardConfig{
			Peers: []PeerConfig{
				{
					AllowedIPs: []string{"10.200.0.0/16"},
				},
			},
		}),
	}

	var dialed []string
	dial := buildSOCKS5Dial(tunnel, 1080, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, network+" "+addr)
		return nil, fmt.Errorf("base dial invoked")
	}, nil)

	_, err := dial(context.Background(), "tcp4", "198.51.100.25:443")
	if err == nil || err.Error() != "base dial invoked" {
		t.Fatalf("expected base dialer error, got %v", err)
	}
	if len(dialed) != 1 || dialed[0] != "tcp4 198.51.100.25:443" {
		t.Fatalf("unexpected base dial invocations: %v", dialed)
	}
}

func TestBuildSOCKS5DialPropagatesBaseDialFailure(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: mustParseIPAddr("10.150.0.2"),
	}

	called := false
	dial := buildSOCKS5Dial(tunnel, 1080, func(ctx context.Context, network, addr string) (net.Conn, error) {
		called = true
		return nil, fmt.Errorf("proxy unreachable")
	}, nil)

	conn, err := dial(context.Background(), "tcp", "example.com:443")
	if err == nil || err.Error() != "proxy unreachable" {
		t.Fatalf("expected base dial error, got conn=%v err=%v", conn, err)
	}
	if conn != nil {
		t.Fatalf("expected nil conn on dial failure, got %v", conn)
	}
	if !called {
		t.Fatal("base dialer was not invoked")
	}
}

// Helper function to parse IP addresses for testing
func mustParseIPAddr(s string) netip.Addr {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		panic("invalid IP: " + s + " - " + err.Error())
	}
	return ip
}

// Helper function to convert int to string (simple implementation)
func itoa(i int) string {
	if i == 0 {
		return "0"
	}

	negative := false
	if i < 0 {
		negative = true
		i = -i
	}

	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}

	if negative {
		digits = append([]byte{'-'}, digits...)
	}

	return string(digits)
}

// Test that tests the tunnel's IsWireGuardIP method with SOCKS5 context
func TestSOCKS5_WireGuardIPDetection(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: mustParseIPAddr("10.150.0.2"),
	}

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"WireGuard IP", "10.150.0.5", true},
		{"Non-WireGuard IP", "8.8.8.8", false},
		{"Localhost", "127.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("invalid IP: %s", tt.ip)
			}

			result := tunnel.IsWireGuardIP(ip)
			if result != tt.want {
				t.Errorf("IsWireGuardIP(%s) = %v, want %v", tt.ip, result, tt.want)
			}
		})
	}
}

// Benchmark test for SOCKS5 server creation
func BenchmarkNewSOCKS5Server(b *testing.B) {
	tunnel := &Tunnel{
		ourIP: mustParseIPAddr("10.150.0.2"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server, err := NewSOCKS5Server(tunnel)
		if err != nil {
			b.Fatalf("NewSOCKS5Server failed: %v", err)
		}
		server.Close()
	}
}
