package main

import (
	"net"
	"testing"
	"time"
)

func TestNewVirtualNetworkStack(t *testing.T) {
	netStack, err := NewVirtualNetworkStack()
	if err != nil {
		t.Fatalf("Failed to create network stack: %v", err)
	}

	if netStack == nil {
		t.Fatal("Network stack should not be nil")
	}

	if netStack.connections == nil {
		t.Error("Connections map should be initialized")
	}

	if netStack.listeningSockets == nil {
		t.Error("Listening sockets map should be initialized")
	}

	if netStack.outgoingPackets == nil {
		t.Error("Outgoing packets channel should be initialized")
	}
}

func TestSetLocalAddress(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()

	_, ipnet, _ := net.ParseCIDR("10.0.0.2/24")
	netStack.SetLocalAddress(ipnet)

	if !netStack.localIP.Equal(ipnet.IP) {
		t.Errorf("Expected local IP %v, got %v", ipnet.IP, netStack.localIP)
	}

	if netStack.localNet.String() != ipnet.String() {
		t.Errorf("Expected local net %v, got %v", ipnet, netStack.localNet)
	}
}

func TestSetLocalAddressIPv6(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()

	_, ipnet, _ := net.ParseCIDR("2001:db8::1/64")
	netStack.SetLocalAddress(ipnet)

	if !netStack.localIP.Equal(ipnet.IP) {
		t.Errorf("Expected local IP %v, got %v", ipnet.IP, netStack.localIP)
	}

	if netStack.localNet.String() != ipnet.String() {
		t.Errorf("Expected local net %v, got %v", ipnet, netStack.localNet)
	}
}

func TestCreateConnection(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()

	conn, err := netStack.CreateConnection("tcp")
	if err != nil {
		t.Fatalf("Failed to create connection: %v", err)
	}

	if conn.ID == 0 {
		t.Error("Connection ID should be non-zero")
	}

	if conn.Type != "tcp" {
		t.Errorf("Expected connection type 'tcp', got %s", conn.Type)
	}

	if conn.State != "created" {
		t.Errorf("Expected connection state 'created', got %s", conn.State)
	}

	// Check if connection is stored
	netStack.mu.RLock()
	storedConn, exists := netStack.connections[conn.ID]
	netStack.mu.RUnlock()

	if !exists {
		t.Error("Connection should be stored in connections map")
	}

	if storedConn.ID != conn.ID {
		t.Error("Stored connection should match created connection")
	}
}

func TestBindConnection(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	conn, _ := netStack.CreateConnection("tcp")

	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 8080}
	err := netStack.BindConnection(conn.ID, addr)
	if err != nil {
		t.Fatalf("Failed to bind connection: %v", err)
	}

	if conn.LocalAddr.String() != addr.String() {
		t.Errorf("Expected local address %s, got %s", addr.String(), conn.LocalAddr.String())
	}
}

func TestBindConnectionIPv6(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	conn, _ := netStack.CreateConnection("tcp")

	addr := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8080}
	err := netStack.BindConnection(conn.ID, addr)
	if err != nil {
		t.Fatalf("Failed to bind connection: %v", err)
	}

	if conn.LocalAddr.String() != addr.String() {
		t.Errorf("Expected local address %s, got %s", addr.String(), conn.LocalAddr.String())
	}
}

func TestBindConnectionNotFound(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()

	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 8080}
	err := netStack.BindConnection(999, addr)
	if err == nil {
		t.Error("Expected error for non-existent connection")
	}
}

func TestListenConnection(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	conn, _ := netStack.CreateConnection("tcp")

	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 8080}
	netStack.BindConnection(conn.ID, addr)

	err := netStack.ListenConnection(conn.ID)
	if err != nil {
		t.Fatalf("Failed to set connection to listening: %v", err)
	}

	if conn.State != "listening" {
		t.Errorf("Expected connection state 'listening', got %s", conn.State)
	}

	// Check if listener is created
	netStack.mu.RLock()
	listener, exists := netStack.listeningSockets[addr.String()]
	netStack.mu.RUnlock()

	if !exists {
		t.Error("Listener should be created")
	}

	if listener.Addr.String() != addr.String() {
		t.Errorf("Expected listener address %s, got %s", addr.String(), listener.Addr.String())
	}
}

func TestListenConnectionNotBound(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	conn, _ := netStack.CreateConnection("tcp")

	err := netStack.ListenConnection(conn.ID)
	if err == nil {
		t.Error("Expected error for unbound connection")
	}
}

func TestConnectConnection(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	_, ipnet, _ := net.ParseCIDR("10.0.0.2/24")
	netStack.SetLocalAddress(ipnet)

	conn, _ := netStack.CreateConnection("tcp")
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80}

	err := netStack.ConnectConnection(conn.ID, remoteAddr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	if conn.State != "connected" {
		t.Errorf("Expected connection state 'connected', got %s", conn.State)
	}

	if conn.RemoteAddr.String() != remoteAddr.String() {
		t.Errorf("Expected remote address %s, got %s", remoteAddr.String(), conn.RemoteAddr.String())
	}

	// Check if local address was auto-assigned
	if conn.LocalAddr == nil {
		t.Error("Local address should be auto-assigned")
	}
}

func TestConnectConnectionIPv6(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	_, ipnet, _ := net.ParseCIDR("2001:db8::1/64")
	netStack.SetLocalAddress(ipnet)

	conn, _ := netStack.CreateConnection("tcp")
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 80}

	err := netStack.ConnectConnection(conn.ID, remoteAddr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	if conn.State != "connected" {
		t.Errorf("Expected connection state 'connected', got %s", conn.State)
	}

	if conn.RemoteAddr.String() != remoteAddr.String() {
		t.Errorf("Expected remote address %s, got %s", remoteAddr.String(), conn.RemoteAddr.String())
	}

	// Check if local address was auto-assigned
	if conn.LocalAddr == nil {
		t.Error("Local address should be auto-assigned")
	}
}

func TestSendData(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	conn, _ := netStack.CreateConnection("tcp")

	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80}
	netStack.ConnectConnection(conn.ID, remoteAddr)

	testData := []byte("hello world")
	err := netStack.SendData(conn.ID, testData)
	if err != nil {
		t.Fatalf("Failed to send data: %v", err)
	}

	// Give the handleConnectionPackets goroutine time to process
	time.Sleep(50 * time.Millisecond)

	// Check if packet was sent to outgoing channel
	select {
	case packet := <-netStack.OutgoingPackets():
		if len(packet) == 0 {
			t.Error("Expected non-empty packet")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Packet should be sent to OutgoingPackets channel")
	}
}

func TestReceiveData(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	conn, _ := netStack.CreateConnection("tcp")

	testData := []byte("hello world")

	// Simulate incoming data
	go func() {
		time.Sleep(10 * time.Millisecond)
		conn.IncomingData <- testData
	}()

	// Wait a bit for the goroutine to send data
	time.Sleep(20 * time.Millisecond)
	data, err := netStack.ReceiveData(conn.ID)
	if err != nil {
		t.Fatalf("Failed to receive data: %v", err)
	}

	if string(data) != string(testData) {
		t.Errorf("Expected data %s, got %s", string(testData), string(data))
	}
}

func TestReceiveDataNoData(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	conn, _ := netStack.CreateConnection("tcp")

	_, err := netStack.ReceiveData(conn.ID)
	if err == nil {
		t.Error("Expected error when no data available")
	}
}

func TestCloseConnection(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	conn, _ := netStack.CreateConnection("tcp")

	err := netStack.CloseConnection(conn.ID)
	if err != nil {
		t.Fatalf("Failed to close connection: %v", err)
	}

	// Check if connection is removed from map
	netStack.mu.RLock()
	_, exists := netStack.connections[conn.ID]
	netStack.mu.RUnlock()

	if exists {
		t.Error("Connection should be removed from connections map")
	}
}

func TestDeliverIncomingPacket(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()

	// Test with packet too short
	shortPacket := []byte{0x45, 0x00}
	err := netStack.DeliverIncomingPacket(shortPacket)
	if err == nil {
		t.Error("Expected error for packet too short")
	}

	// Test with unsupported protocol
	unsupportedProtocolPacket := make([]byte, 20)
	unsupportedProtocolPacket[0] = 0x45 // IPv4, header length 20
	unsupportedProtocolPacket[9] = 1    // ICMP protocol
	err = netStack.DeliverIncomingPacket(unsupportedProtocolPacket)
	if err == nil {
		t.Error("Expected error for unsupported protocol")
	}

	// Test with unsupported IP version
	unsupportedVersionPacket := make([]byte, 20)
	unsupportedVersionPacket[0] = 0x75 // Version 7
	err = netStack.DeliverIncomingPacket(unsupportedVersionPacket)
	if err == nil {
		t.Error("Expected error for unsupported IP version")
	}
}

func TestDeliverIncomingIPv6Packet(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()

	// Test with IPv6 packet too short
	shortIPv6Packet := make([]byte, 20)
	shortIPv6Packet[0] = 0x60 // IPv6
	err := netStack.DeliverIncomingPacket(shortIPv6Packet)
	if err == nil {
		t.Error("Expected error for IPv6 packet too short")
	}

	// Test with IPv6 unsupported protocol
	unsupportedIPv6Packet := make([]byte, 40)
	unsupportedIPv6Packet[0] = 0x60 // IPv6
	unsupportedIPv6Packet[6] = 1    // ICMP next header
	err = netStack.DeliverIncomingPacket(unsupportedIPv6Packet)
	if err == nil {
		t.Error("Expected error for unsupported IPv6 protocol")
	}
}

func TestCreateTCPPacket(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	conn, _ := netStack.CreateConnection("tcp")

	localAddr := &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 8080}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80}
	conn.LocalAddr = localAddr
	conn.RemoteAddr = remoteAddr

	testData := []byte("test data")
	packet := netStack.createTCPPacket(conn, testData, false, true, false)

	if len(packet) < 40 {
		t.Error("TCP packet should be at least 40 bytes (20 IP + 20 TCP)")
	}

	// Check IP version and header length
	if packet[0] != 0x45 {
		t.Error("IP version should be 4 and header length should be 20")
	}

	// Check protocol
	if packet[9] != 6 {
		t.Error("Protocol should be TCP (6)")
	}

	// Check source and destination IPs
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	if !srcIP.Equal(localAddr.IP) {
		t.Errorf("Source IP should be %v, got %v", localAddr.IP, srcIP)
	}

	if !dstIP.Equal(remoteAddr.IP) {
		t.Errorf("Destination IP should be %v, got %v", remoteAddr.IP, dstIP)
	}
}

func TestCreateTCPPacketIPv6(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	conn, _ := netStack.CreateConnection("tcp")

	localAddr := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8080}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 80}
	conn.LocalAddr = localAddr
	conn.RemoteAddr = remoteAddr

	testData := []byte("test data")
	packet := netStack.createTCPPacket(conn, testData, false, true, false)

	if len(packet) < 60 {
		t.Error("IPv6 TCP packet should be at least 60 bytes (40 IP + 20 TCP)")
	}

	// Check IP version
	if packet[0] != 0x60 {
		t.Error("IP version should be 6")
	}

	// Check next header (TCP)
	if packet[6] != 6 {
		t.Error("Next header should be TCP (6)")
	}

	// Check source and destination IPs
	srcIP := net.IP(packet[8:24])
	dstIP := net.IP(packet[24:40])

	if !srcIP.Equal(localAddr.IP) {
		t.Errorf("Source IP should be %v, got %v", localAddr.IP, srcIP)
	}

	if !dstIP.Equal(remoteAddr.IP) {
		t.Errorf("Destination IP should be %v, got %v", remoteAddr.IP, dstIP)
	}
}

func TestCreateUDPPacket(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	conn, _ := netStack.CreateConnection("udp")

	localAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 8080}
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80}
	conn.LocalAddr = localAddr
	conn.RemoteAddr = remoteAddr

	testData := []byte("test data")
	packet := netStack.createUDPPacket(conn, testData)

	if len(packet) < 28 {
		t.Error("UDP packet should be at least 28 bytes (20 IP + 8 UDP)")
	}

	// Check IP version and header length
	if packet[0] != 0x45 {
		t.Error("IP version should be 4 and header length should be 20")
	}

	// Check protocol
	if packet[9] != 17 {
		t.Error("Protocol should be UDP (17)")
	}

	// Check source and destination IPs
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	if !srcIP.Equal(localAddr.IP) {
		t.Errorf("Source IP should be %v, got %v", localAddr.IP, srcIP)
	}

	if !dstIP.Equal(remoteAddr.IP) {
		t.Errorf("Destination IP should be %v, got %v", remoteAddr.IP, dstIP)
	}
}

func TestCreateUDPPacketIPv6(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()
	conn, _ := netStack.CreateConnection("udp")

	localAddr := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8080}
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 80}
	conn.LocalAddr = localAddr
	conn.RemoteAddr = remoteAddr

	testData := []byte("test data")
	packet := netStack.createUDPPacket(conn, testData)

	if len(packet) < 48 {
		t.Error("IPv6 UDP packet should be at least 48 bytes (40 IP + 8 UDP)")
	}

	// Check IP version
	if packet[0] != 0x60 {
		t.Error("IP version should be 6")
	}

	// Check next header (UDP)
	if packet[6] != 17 {
		t.Error("Next header should be UDP (17)")
	}

	// Check source and destination IPs
	srcIP := net.IP(packet[8:24])
	dstIP := net.IP(packet[24:40])

	if !srcIP.Equal(localAddr.IP) {
		t.Errorf("Source IP should be %v, got %v", localAddr.IP, srcIP)
	}

	if !dstIP.Equal(remoteAddr.IP) {
		t.Errorf("Destination IP should be %v, got %v", remoteAddr.IP, dstIP)
	}
}

func TestOutgoingPacketsChannel(t *testing.T) {
	netStack, _ := NewVirtualNetworkStack()

	// Test that we can get the channel
	ch := netStack.OutgoingPackets()
	if ch == nil {
		t.Error("Outgoing packets channel should not be nil")
	}

	// Test that we can send to the channel
	testPacket := []byte("test packet")
	go func() {
		netStack.outgoingPackets <- testPacket
	}()

	select {
	case packet := <-ch:
		if string(packet) != string(testPacket) {
			t.Errorf("Expected packet %s, got %s", string(testPacket), string(packet))
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Should receive packet from channel")
	}
}
