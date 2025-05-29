package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestNewIPCServer(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()

	// Create a minimal WireGuard config for testing
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			PrivateKey: "YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==",
		},
	}
	_, ipnet, _ := net.ParseCIDR("10.0.0.2/24")
	config.Interface.Address = ipnet

	// Create a mock WireGuard proxy for testing
	wgProxy := &WireGuardProxy{
		config: config,
	}

	server, err := NewIPCServer(netStack, wgProxy)
	if err != nil {
		t.Fatalf("Failed to create IPC server: %v", err)
	}

	if server == nil {
		t.Fatal("IPC server should not be nil")
	}

	if server.socketPath == "" {
		t.Error("Socket path should not be empty")
	}

	if server.netStack != netStack {
		t.Error("Network stack should be set correctly")
	}

	if server.wgProxy != wgProxy {
		t.Error("WireGuard proxy should be set correctly")
	}
}

func TestSocketPath(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			PrivateKey: "YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==",
		},
	}
	_, ipnet, _ := net.ParseCIDR("10.0.0.2/24")
	config.Interface.Address = ipnet

	wgProxy := &WireGuardProxy{config: config}
	server, _ := NewIPCServer(netStack, wgProxy)

	socketPath := server.SocketPath()
	if socketPath == "" {
		t.Error("Socket path should not be empty")
	}

	// Check that socket path is absolute
	if !filepath.IsAbs(socketPath) {
		t.Error("Socket path should be absolute")
	}
}

func TestHandleSocketMessage(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			PrivateKey: "YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==",
		},
	}
	_, ipnet, _ := net.ParseCIDR("10.0.0.2/24")
	config.Interface.Address = ipnet

	wgProxy := &WireGuardProxy{config: config}
	server, _ := NewIPCServer(netStack, wgProxy)

	// Test TCP socket creation
	msg := &IPCMessage{
		Type:     "socket",
		Domain:   2, // AF_INET
		SockType: 1, // SOCK_STREAM
		Protocol: 0,
	}

	response := server.handleSocket(msg)
	if !response.Success {
		t.Errorf("Expected success, got error: %s", response.Error)
	}

	if response.ConnID == 0 {
		t.Error("Connection ID should be non-zero")
	}

	// Test UDP socket creation
	msg.SockType = 2 // SOCK_DGRAM
	response = server.handleSocket(msg)
	if !response.Success {
		t.Errorf("Expected success, got error: %s", response.Error)
	}

	// Test unsupported domain
	msg.Domain = 10 // AF_INET6 (unsupported)
	response = server.handleSocket(msg)
	if response.Success {
		t.Error("Expected failure for unsupported domain")
	}

	// Test unsupported socket type
	msg.Domain = 2
	msg.SockType = 3 // SOCK_RAW (unsupported)
	response = server.handleSocket(msg)
	if response.Success {
		t.Error("Expected failure for unsupported socket type")
	}
}

func TestHandleBindMessage(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			PrivateKey: "YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==",
		},
	}
	_, ipnet, _ := net.ParseCIDR("10.0.0.2/24")
	config.Interface.Address = ipnet

	wgProxy := &WireGuardProxy{config: config}
	server, _ := NewIPCServer(netStack, wgProxy)

	// Create a connection first
	conn, _ := netStack.CreateConnection("tcp")

	msg := &IPCMessage{
		Type:    "bind",
		ConnID:  conn.ID,
		Address: "10.0.0.2",
		Port:    8080,
	}

	response := server.handleBind(msg)
	if !response.Success {
		t.Errorf("Expected success, got error: %s", response.Error)
	}

	// Test bind with non-existent connection
	msg.ConnID = 999
	response = server.handleBind(msg)
	if response.Success {
		t.Error("Expected failure for non-existent connection")
	}
}

func TestHandleConnectMessage(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			PrivateKey: "YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==",
		},
	}
	_, ipnet, _ := net.ParseCIDR("10.0.0.2/24")
	config.Interface.Address = ipnet

	wgProxy := &WireGuardProxy{config: config}
	server, _ := NewIPCServer(netStack, wgProxy)

	// Create a connection first
	conn, _ := netStack.CreateConnection("tcp")

	msg := &IPCMessage{
		Type:    "connect",
		ConnID:  conn.ID,
		Address: "192.168.1.1",
		Port:    80,
	}

	response := server.handleConnect(msg)
	if !response.Success {
		t.Errorf("Expected success, got error: %s", response.Error)
	}

	// Test connect with non-existent connection
	msg.ConnID = 999
	response = server.handleConnect(msg)
	if response.Success {
		t.Error("Expected failure for non-existent connection")
	}
}

func TestHandleSendMessage(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			PrivateKey: "YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==",
		},
	}
	_, ipnet, _ := net.ParseCIDR("10.0.0.2/24")
	config.Interface.Address = ipnet

	wgProxy := &WireGuardProxy{config: config}
	server, _ := NewIPCServer(netStack, wgProxy)

	// Create and connect a connection
	conn, _ := netStack.CreateConnection("tcp")
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80}
	netStack.ConnectConnection(conn.ID, remoteAddr)

	testData := []byte("hello world")
	msg := &IPCMessage{
		Type:   "send",
		ConnID: conn.ID,
		Data:   testData,
	}

	response := server.handleSend(msg)
	if !response.Success {
		t.Errorf("Expected success, got error: %s", response.Error)
	}
}

func TestHandleRecvMessage(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			PrivateKey: "YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==",
		},
	}
	_, ipnet, _ := net.ParseCIDR("10.0.0.2/24")
	config.Interface.Address = ipnet

	wgProxy := &WireGuardProxy{config: config}
	server, _ := NewIPCServer(netStack, wgProxy)

	// Create a connection
	conn, _ := netStack.CreateConnection("tcp")

	// Put some data in the incoming channel
	testData := []byte("hello world")
	go func() {
		time.Sleep(10 * time.Millisecond)
		conn.IncomingData <- testData
	}()

	msg := &IPCMessage{
		Type:   "recv",
		ConnID: conn.ID,
	}

	response := server.handleRecv(msg)
	if !response.Success {
		t.Errorf("Expected success, got error: %s", response.Error)
	}

	if string(response.Data) != string(testData) {
		t.Errorf("Expected data %s, got %s", string(testData), string(response.Data))
	}
}

func TestHandleCloseMessage(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			PrivateKey: "YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==",
		},
	}
	_, ipnet, _ := net.ParseCIDR("10.0.0.2/24")
	config.Interface.Address = ipnet

	wgProxy := &WireGuardProxy{config: config}
	server, _ := NewIPCServer(netStack, wgProxy)

	// Create a connection
	conn, _ := netStack.CreateConnection("tcp")

	msg := &IPCMessage{
		Type:   "close",
		ConnID: conn.ID,
	}

	response := server.handleClose(msg)
	if !response.Success {
		t.Errorf("Expected success, got error: %s", response.Error)
	}

	// Verify connection was actually closed
	netStack.mu.RLock()
	_, exists := netStack.connections[conn.ID]
	netStack.mu.RUnlock()

	if exists {
		t.Error("Connection should have been removed")
	}
}

func TestHandleUnknownMessage(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	config := &WireGuardConfig{
		Interface: InterfaceConfig{
			PrivateKey: "YWJjZGVmZ2hpamtsb21ub3Bxcnp0dXZ3eHl6MTIzNDU2Nzg5MA==",
		},
	}
	_, ipnet, _ := net.ParseCIDR("10.0.0.2/24")
	config.Interface.Address = ipnet

	wgProxy := &WireGuardProxy{config: config}
	server, _ := NewIPCServer(netStack, wgProxy)

	msg := &IPCMessage{
		Type: "unknown",
	}

	response := server.handleMessage(msg)
	if response.Success {
		t.Error("Expected failure for unknown message type")
	}

	if response.Error == "" {
		t.Error("Expected error message for unknown type")
	}
}

func TestIPCMessageSerialization(t *testing.T) {
	msg := &IPCMessage{
		Type:     "socket",
		ConnID:   123,
		SocketFD: 456,
		Domain:   2,
		SockType: 1,
		Protocol: 0,
		Address:  "10.0.0.2",
		Port:     8080,
		Data:     []byte("test data"),
		Error:    "",
	}

	// Test JSON marshaling
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal IPC message: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaled IPCMessage
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal IPC message: %v", err)
	}

	// Verify fields
	if unmarshaled.Type != msg.Type {
		t.Errorf("Type mismatch: expected %s, got %s", msg.Type, unmarshaled.Type)
	}
	if unmarshaled.ConnID != msg.ConnID {
		t.Errorf("ConnID mismatch: expected %d, got %d", msg.ConnID, unmarshaled.ConnID)
	}
	if unmarshaled.Address != msg.Address {
		t.Errorf("Address mismatch: expected %s, got %s", msg.Address, unmarshaled.Address)
	}
	if string(unmarshaled.Data) != string(msg.Data) {
		t.Errorf("Data mismatch: expected %s, got %s", string(msg.Data), string(unmarshaled.Data))
	}
}

func TestIPCResponseSerialization(t *testing.T) {
	response := &IPCResponse{
		Success: true,
		ConnID:  123,
		Data:    []byte("response data"),
		Error:   "",
	}

	// Test JSON marshaling
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal IPC response: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaled IPCResponse
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal IPC response: %v", err)
	}

	// Verify fields
	if unmarshaled.Success != response.Success {
		t.Errorf("Success mismatch: expected %t, got %t", response.Success, unmarshaled.Success)
	}
	if unmarshaled.ConnID != response.ConnID {
		t.Errorf("ConnID mismatch: expected %d, got %d", response.ConnID, unmarshaled.ConnID)
	}
	if string(unmarshaled.Data) != string(response.Data) {
		t.Errorf("Data mismatch: expected %s, got %s", string(response.Data), string(unmarshaled.Data))
	}
}
