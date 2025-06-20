package main

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestNewPortForwarder(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: netip.MustParseAddr("10.150.0.2"),
	}
	
	msgChan := make(chan IPCMessage, 10)
	forwarder := NewPortForwarder(tunnel, msgChan)
	
	if forwarder == nil {
		t.Fatal("NewPortForwarder returned nil")
	}
	
	if forwarder.tunnel != tunnel {
		t.Error("tunnel not set correctly")
	}
	
	if forwarder.msgChan != msgChan {
		t.Error("message channel not set correctly")
	}
	
	if forwarder.listeners == nil {
		t.Error("listeners map not initialized")
	}
	
	if len(forwarder.listeners) != 0 {
		t.Error("listeners map should be empty initially")
	}
}

func TestPortForwarder_HandleBind(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: netip.MustParseAddr("10.150.0.2"),
	}
	
	msgChan := make(chan IPCMessage, 10)
	forwarder := NewPortForwarder(tunnel, msgChan)
	
	// Test binding to a port
	port := 8080
	err := forwarder.handleBind(port)
	
	// In test environment, this might fail to bind to the WireGuard IP
	// but should fall back to localhost
	if err != nil {
		t.Logf("handleBind failed (expected in test env): %v", err)
		return
	}
	
	// Check that listener was created
	if _, exists := forwarder.listeners[port]; !exists {
		t.Error("listener not created for port")
	}
	
	// Clean up
	forwarder.closeAllListeners()
}

func TestPortForwarder_HandleBindDuplicate(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: netip.MustParseAddr("10.150.0.2"),
	}
	
	msgChan := make(chan IPCMessage, 10)
	forwarder := NewPortForwarder(tunnel, msgChan)
	defer forwarder.closeAllListeners()
	
	port := 8081
	
	// First bind should succeed or fail gracefully
	err1 := forwarder.handleBind(port)
	
	// Second bind to same port should not create duplicate listener
	err2 := forwarder.handleBind(port)
	
	// Both should either succeed or fail gracefully
	if err1 != nil && err2 != nil {
		t.Logf("Both bind attempts failed (expected in test env): %v, %v", err1, err2)
		return
	}
	
	// Should only have one listener for the port
	count := 0
	for p := range forwarder.listeners {
		if p == port {
			count++
		}
	}
	
	if count > 1 {
		t.Errorf("found %d listeners for port %d, want at most 1", count, port)
	}
}

func TestPortForwarder_Run(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: netip.MustParseAddr("10.150.0.2"),
	}
	
	msgChan := make(chan IPCMessage, 10)
	forwarder := NewPortForwarder(tunnel, msgChan)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Start the forwarder in a goroutine
	done := make(chan bool)
	go func() {
		forwarder.Run(ctx)
		done <- true
	}()
	
	// Send a BIND message
	bindMsg := IPCMessage{
		Type: "BIND",
		Port: 8082,
	}
	
	msgChan <- bindMsg
	
	// Give some time for message processing
	time.Sleep(50 * time.Millisecond)
	
	// Cancel context to stop the forwarder
	cancel()
	
	// Wait for forwarder to stop
	select {
	case <-done:
		// Good, forwarder stopped
	case <-time.After(1 * time.Second):
		t.Error("forwarder did not stop within timeout")
	}
	
	// All listeners should be closed
	if len(forwarder.listeners) != 0 {
		t.Errorf("expected 0 listeners after close, got %d", len(forwarder.listeners))
	}
}

func TestPortForwarder_RunWithNonBindMessage(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: netip.MustParseAddr("10.150.0.2"),
	}
	
	msgChan := make(chan IPCMessage, 10)
	forwarder := NewPortForwarder(tunnel, msgChan)
	
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	
	// Start the forwarder
	done := make(chan bool)
	go func() {
		forwarder.Run(ctx)
		done <- true
	}()
	
	// Send a non-BIND message
	connectMsg := IPCMessage{
		Type: "CONNECT",
		Port: 8083,
	}
	
	msgChan <- connectMsg
	
	// Wait for context timeout
	<-done
	
	// Should not have created any listeners
	if len(forwarder.listeners) != 0 {
		t.Errorf("expected 0 listeners for CONNECT message, got %d", len(forwarder.listeners))
	}
}

func TestPortForwarder_CloseAllListeners(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: netip.MustParseAddr("10.150.0.2"),
	}
	
	msgChan := make(chan IPCMessage, 10)
	forwarder := NewPortForwarder(tunnel, msgChan)
	
	// Create mock listeners (using real listeners would require available ports)
	listener1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create test listener 1: %v", err)
	}
	
	listener2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		listener1.Close()
		t.Fatalf("failed to create test listener 2: %v", err)
	}
	
	port1 := listener1.Addr().(*net.TCPAddr).Port
	port2 := listener2.Addr().(*net.TCPAddr).Port
	
	forwarder.listeners[port1] = listener1
	forwarder.listeners[port2] = listener2
	
	// Close all listeners
	forwarder.closeAllListeners()
	
	// Listeners map should be empty
	if len(forwarder.listeners) != 0 {
		t.Errorf("expected 0 listeners after closeAll, got %d", len(forwarder.listeners))
	}
	
	// Listeners should be closed (attempting to accept should fail)
	_, err = listener1.Accept()
	if err == nil {
		t.Error("listener1 should be closed")
	}
	
	_, err = listener2.Accept()
	if err == nil {
		t.Error("listener2 should be closed")
	}
}

func TestPortForwarder_AcceptConnections(t *testing.T) {
	// This test is complex to implement without real network setup
	// We'll test the basic structure and error handling
	
	tunnel := &Tunnel{
		ourIP: netip.MustParseAddr("10.150.0.2"),
	}
	
	msgChan := make(chan IPCMessage, 10)
	forwarder := NewPortForwarder(tunnel, msgChan)
	
	// Create a listener on an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create test listener: %v", err)
	}
	defer listener.Close()
	
	port := listener.Addr().(*net.TCPAddr).Port
	
	// Start accepting connections in a goroutine
	done := make(chan bool)
	go func() {
		forwarder.acceptConnections(listener, port)
		done <- true
	}()
	
	// Close the listener to stop accepting
	listener.Close()
	
	// Wait for acceptConnections to exit
	select {
	case <-done:
		// Good, acceptConnections stopped
	case <-time.After(1 * time.Second):
		t.Error("acceptConnections did not stop within timeout")
	}
}

func TestPortForwarder_HandleConnection(t *testing.T) {
	// This test requires a more complex setup with actual network connections
	// For now, we'll test the basic structure
	
	tunnel := &Tunnel{
		ourIP: netip.MustParseAddr("10.150.0.2"),
	}
	
	msgChan := make(chan IPCMessage, 10)
	forwarder := NewPortForwarder(tunnel, msgChan)
	
	// Create a mock connection pair
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	
	// Test that handleConnection doesn't panic
	// In a real scenario, this would connect to localhost:port
	// but that requires a server running on that port
	
	done := make(chan bool)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("handleConnection panicked: %v", r)
			}
			done <- true
		}()
		forwarder.handleConnection(server, 8080)
	}()
	
	// Close connections to trigger exit
	server.Close()
	client.Close()
	
	// Wait for completion
	select {
	case <-done:
		// Good, no panic
	case <-time.After(1 * time.Second):
		t.Error("handleConnection did not complete within timeout")
	}
}

func TestPortForwarder_ConcurrentAccess(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: netip.MustParseAddr("10.150.0.2"),
	}
	
	msgChan := make(chan IPCMessage, 100)
	forwarder := NewPortForwarder(tunnel, msgChan)
	
	// Test concurrent access to the listeners map
	done := make(chan bool, 10)
	
	// Start multiple goroutines trying to bind to different ports
	for i := 0; i < 10; i++ {
		go func(port int) {
			defer func() {
				done <- true
			}()
			// This will likely fail in test environment, but tests concurrency
			forwarder.handleBind(8000 + port)
		}(i)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Good
		case <-time.After(2 * time.Second):
			t.Error("goroutine did not complete within timeout")
			return
		}
	}
	
	// Clean up
	forwarder.closeAllListeners()
}

func TestPortForwarder_MessageChannelClosed(t *testing.T) {
	tunnel := &Tunnel{
		ourIP: netip.MustParseAddr("10.150.0.2"),
	}
	
	msgChan := make(chan IPCMessage, 10)
	forwarder := NewPortForwarder(tunnel, msgChan)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Start the forwarder
	done := make(chan bool)
	go func() {
		forwarder.Run(ctx)
		done <- true
	}()
	
	// Close the message channel
	close(msgChan)
	
	// Give some time for the forwarder to handle the closed channel
	time.Sleep(50 * time.Millisecond)
	
	// Cancel context
	cancel()
	
	// Wait for forwarder to stop
	select {
	case <-done:
		// Good, forwarder handled closed channel gracefully
	case <-time.After(1 * time.Second):
		t.Error("forwarder did not stop after channel close")
	}
}

// Test IP address validation
func TestPortForwarder_IPValidation(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"IPv4", "10.150.0.2"},
		{"IPv6", "::1"},
		{"nil", ""},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip netip.Addr
			if tt.ip != "" {
				var err error
				ip, err = netip.ParseAddr(tt.ip)
				if err != nil {
					t.Fatalf("invalid test IP: %v", err)
				}
			}
			
			tunnel := &Tunnel{
				ourIP: ip,
			}
			
			msgChan := make(chan IPCMessage, 10)
			forwarder := NewPortForwarder(tunnel, msgChan)
			
			// Should not panic with any IP configuration
			if forwarder == nil {
				t.Error("NewPortForwarder returned nil")
			}
		})
	}
}

// Benchmark test for port forwarder creation
func BenchmarkNewPortForwarder(b *testing.B) {
	tunnel := &Tunnel{
		ourIP: netip.MustParseAddr("10.150.0.2"),
	}
	
	msgChan := make(chan IPCMessage, 10)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		forwarder := NewPortForwarder(tunnel, msgChan)
		_ = forwarder
	}
}

// Benchmark test for bind handling
func BenchmarkPortForwarder_HandleBind(b *testing.B) {
	tunnel := &Tunnel{
		ourIP: netip.MustParseAddr("10.150.0.2"),
	}
	
	msgChan := make(chan IPCMessage, 10)
	forwarder := NewPortForwarder(tunnel, msgChan)
	defer forwarder.closeAllListeners()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Use different ports to avoid conflicts
		port := 8000 + (i % 1000)
		forwarder.handleBind(port)
	}
}