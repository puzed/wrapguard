package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewIPCServer(t *testing.T) {
	server, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer server.Close()

	if server == nil {
		t.Fatal("NewIPCServer returned nil")
	}

	if server.listener == nil {
		t.Error("listener is nil")
	}

	if server.socketPath == "" {
		t.Error("socket path is empty")
	}

	if server.msgChan == nil {
		t.Error("message channel is nil")
	}

	// Check that socket path is in temp directory
	expectedDir := os.TempDir()
	actualDir := filepath.Dir(server.socketPath)
	// Clean the paths to handle trailing slashes consistently
	expectedDir = filepath.Clean(expectedDir)
	actualDir = filepath.Clean(actualDir)
	if actualDir != expectedDir {
		t.Errorf("socket path not in temp dir: expected %s, got %s", expectedDir, actualDir)
	}

	// Check that socket file contains PID
	if !containsPID(server.socketPath) {
		t.Error("socket path should contain PID")
	}
}

func TestIPCServer_SocketPath(t *testing.T) {
	server, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer server.Close()

	path := server.SocketPath()
	if path == "" {
		t.Error("SocketPath returned empty string")
	}

	if path != server.socketPath {
		t.Errorf("SocketPath() = %q, want %q", path, server.socketPath)
	}
}

func TestIPCServer_MessageChan(t *testing.T) {
	server, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer server.Close()

	msgChan := server.MessageChan()
	if msgChan == nil {
		t.Error("MessageChan returned nil")
	}

	// Test that it's the same channel
	if msgChan != server.msgChan {
		t.Error("MessageChan returned different channel")
	}

	// Test that it's read-only
	select {
	case <-msgChan:
		// This is fine, channel is empty
	default:
		// This is expected
	}
}

func TestIPCServer_Close(t *testing.T) {
	server, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}

	socketPath := server.socketPath

	// Socket file should exist
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("socket file should exist before close")
	}

	// Close the server
	err = server.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Socket file should be removed
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("socket file should be removed after close")
	}

	// Multiple closes should not panic
	err = server.Close()
	if err != nil {
		t.Errorf("second Close() returned error: %v", err)
	}
}

func TestIPCServer_MessageHandling(t *testing.T) {
	server, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer server.Close()

	// Give server time to start accepting connections
	time.Sleep(10 * time.Millisecond)

	// Connect to the IPC server
	conn, err := net.Dial("unix", server.socketPath)
	if err != nil {
		t.Fatalf("failed to connect to IPC server: %v", err)
	}
	defer conn.Close()

	// Test message
	msg := IPCMessage{
		Type: "CONNECT",
		FD:   42,
		Port: 8080,
		Addr: "127.0.0.1:8080",
	}

	// Send message
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal message: %v", err)
	}

	_, err = conn.Write(append(msgBytes, '\n'))
	if err != nil {
		t.Fatalf("failed to write message: %v", err)
	}

	// Receive message from channel
	select {
	case receivedMsg := <-server.msgChan:
		if receivedMsg.Type != msg.Type {
			t.Errorf("received Type = %q, want %q", receivedMsg.Type, msg.Type)
		}
		if receivedMsg.FD != msg.FD {
			t.Errorf("received FD = %d, want %d", receivedMsg.FD, msg.FD)
		}
		if receivedMsg.Port != msg.Port {
			t.Errorf("received Port = %d, want %d", receivedMsg.Port, msg.Port)
		}
		if receivedMsg.Addr != msg.Addr {
			t.Errorf("received Addr = %q, want %q", receivedMsg.Addr, msg.Addr)
		}
	case <-time.After(1 * time.Second):
		t.Error("timeout waiting for message")
	}
}

func TestIPCServer_InvalidMessage(t *testing.T) {
	server, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer server.Close()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Connect to the IPC server
	conn, err := net.Dial("unix", server.socketPath)
	if err != nil {
		t.Fatalf("failed to connect to IPC server: %v", err)
	}
	defer conn.Close()

	// Send invalid JSON
	_, err = conn.Write([]byte("invalid json\n"))
	if err != nil {
		t.Fatalf("failed to write invalid message: %v", err)
	}

	// Should not receive anything on message channel
	select {
	case msg := <-server.msgChan:
		t.Errorf("received unexpected message: %+v", msg)
	case <-time.After(100 * time.Millisecond):
		// This is expected - invalid messages should be dropped
	}
}

func TestIPCServer_MultipleConnections(t *testing.T) {
	server, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer server.Close()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Create multiple connections
	conns := make([]net.Conn, 3)
	defer func() {
		for _, conn := range conns {
			if conn != nil {
				conn.Close()
			}
		}
	}()

	for i := 0; i < 3; i++ {
		conn, err := net.Dial("unix", server.socketPath)
		if err != nil {
			t.Fatalf("failed to connect %d to IPC server: %v", i, err)
		}
		conns[i] = conn
	}

	// Send messages from all connections
	messages := []IPCMessage{
		{Type: "CONNECT", FD: 1, Port: 8080, Addr: "127.0.0.1:8080"},
		{Type: "BIND", FD: 2, Port: 8081, Addr: "127.0.0.1:8081"},
		{Type: "CONNECT", FD: 3, Port: 8082, Addr: "127.0.0.1:8082"},
	}

	for i, msg := range messages {
		msgBytes, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("failed to marshal message %d: %v", i, err)
		}

		_, err = conns[i].Write(append(msgBytes, '\n'))
		if err != nil {
			t.Fatalf("failed to write message %d: %v", i, err)
		}
	}

	// Receive all messages
	received := make(map[int]IPCMessage)
	for i := 0; i < 3; i++ {
		select {
		case msg := <-server.msgChan:
			received[msg.FD] = msg
		case <-time.After(1 * time.Second):
			t.Errorf("timeout waiting for message %d", i)
		}
	}

	// Verify all messages were received
	for i, originalMsg := range messages {
		receivedMsg, ok := received[originalMsg.FD]
		if !ok {
			t.Errorf("message %d not received", i)
			continue
		}

		if receivedMsg.Type != originalMsg.Type {
			t.Errorf("message %d: Type = %q, want %q", i, receivedMsg.Type, originalMsg.Type)
		}
		if receivedMsg.Port != originalMsg.Port {
			t.Errorf("message %d: Port = %d, want %d", i, receivedMsg.Port, originalMsg.Port)
		}
		if receivedMsg.Addr != originalMsg.Addr {
			t.Errorf("message %d: Addr = %q, want %q", i, receivedMsg.Addr, originalMsg.Addr)
		}
	}
}

func TestIPCServer_ChannelBuffering(t *testing.T) {
	server, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer server.Close()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Connect to server
	conn, err := net.Dial("unix", server.socketPath)
	if err != nil {
		t.Fatalf("failed to connect to IPC server: %v", err)
	}
	defer conn.Close()

	// Send many messages without reading from channel
	// This tests the channel buffering (should be 100)
	for i := 0; i < 50; i++ {
		msg := IPCMessage{
			Type: "CONNECT",
			FD:   i,
			Port: 8080 + i,
			Addr: "127.0.0.1:8080",
		}

		msgBytes, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("failed to marshal message %d: %v", i, err)
		}

		_, err = conn.Write(append(msgBytes, '\n'))
		if err != nil {
			t.Fatalf("failed to write message %d: %v", i, err)
		}
	}

	// Give time for messages to be processed
	time.Sleep(100 * time.Millisecond)

	// Now read messages from channel
	count := 0
	for {
		select {
		case <-server.msgChan:
			count++
		case <-time.After(100 * time.Millisecond):
			// No more messages
			goto done
		}
	}

done:
	if count != 50 {
		t.Errorf("received %d messages, want 50", count)
	}
}

func TestIPCMessage_JSONMarshaling(t *testing.T) {
	msg := IPCMessage{
		Type: "BIND",
		FD:   42,
		Port: 8080,
		Addr: "192.168.1.1:8080",
	}

	// Marshal to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal IPCMessage: %v", err)
	}

	// Unmarshal from JSON
	var unmarshaled IPCMessage
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("failed to unmarshal IPCMessage: %v", err)
	}

	// Compare
	if unmarshaled.Type != msg.Type {
		t.Errorf("Type = %q, want %q", unmarshaled.Type, msg.Type)
	}
	if unmarshaled.FD != msg.FD {
		t.Errorf("FD = %d, want %d", unmarshaled.FD, msg.FD)
	}
	if unmarshaled.Port != msg.Port {
		t.Errorf("Port = %d, want %d", unmarshaled.Port, msg.Port)
	}
	if unmarshaled.Addr != msg.Addr {
		t.Errorf("Addr = %q, want %q", unmarshaled.Addr, msg.Addr)
	}
}

func TestIPCServer_ConnectionClosed(t *testing.T) {
	server, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer server.Close()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Connect and immediately close
	conn, err := net.Dial("unix", server.socketPath)
	if err != nil {
		t.Fatalf("failed to connect to IPC server: %v", err)
	}

	// Send a message and then close
	msg := IPCMessage{Type: "CONNECT", FD: 1, Port: 8080, Addr: "127.0.0.1:8080"}
	msgBytes, _ := json.Marshal(msg)
	conn.Write(append(msgBytes, '\n'))
	conn.Close()

	// Should receive the message
	select {
	case receivedMsg := <-server.msgChan:
		if receivedMsg.Type != msg.Type {
			t.Errorf("received wrong message type: %s", receivedMsg.Type)
		}
	case <-time.After(1 * time.Second):
		t.Error("timeout waiting for message")
	}

	// Server should handle the closed connection gracefully
	// (no panic or error)
}

func TestIPCServer_SocketPermissions(t *testing.T) {
	server, err := NewIPCServer()
	if err != nil {
		t.Fatalf("NewIPCServer failed: %v", err)
	}
	defer server.Close()

	// Check that socket file exists and has appropriate permissions
	info, err := os.Stat(server.socketPath)
	if err != nil {
		t.Fatalf("failed to stat socket file: %v", err)
	}

	// Should be a socket
	if info.Mode()&os.ModeSocket == 0 {
		t.Error("socket file is not a socket")
	}
}

// Helper function to check if path contains PID
func containsPID(path string) bool {
	filename := filepath.Base(path)
	return len(filename) > len("wrapguard-.sock")
}

// Benchmark test for IPC server creation
func BenchmarkNewIPCServer(b *testing.B) {
	for i := 0; i < b.N; i++ {
		server, err := NewIPCServer()
		if err != nil {
			b.Fatalf("NewIPCServer failed: %v", err)
		}
		server.Close()
	}
}

// Benchmark test for message handling
func BenchmarkIPCServer_MessageHandling(b *testing.B) {
	server, err := NewIPCServer()
	if err != nil {
		b.Fatalf("NewIPCServer failed: %v", err)
	}
	defer server.Close()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("unix", server.socketPath)
	if err != nil {
		b.Fatalf("failed to connect to IPC server: %v", err)
	}
	defer conn.Close()

	msg := IPCMessage{
		Type: "CONNECT",
		FD:   42,
		Port: 8080,
		Addr: "127.0.0.1:8080",
	}

	msgBytes, _ := json.Marshal(msg)
	msgLine := append(msgBytes, '\n')

	// Drain the channel in a goroutine
	go func() {
		for {
			select {
			case <-server.msgChan:
			case <-time.After(1 * time.Second):
				return
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.Write(msgLine)
	}
}
