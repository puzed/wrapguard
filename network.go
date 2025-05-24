package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// VirtualNetworkStack manages virtual connections and packet routing
type VirtualNetworkStack struct {
	mu               sync.RWMutex
	connections      map[uint32]*VirtualConnection
	listeningSockets map[string]*VirtualListener
	outgoingPackets  chan []byte
	nextConnID       uint32
	localIP          net.IP
	localNet         *net.IPNet
}

// VirtualConnection represents a virtual network connection
type VirtualConnection struct {
	ID         uint32
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	Type       string // "tcp" or "udp"
	State      string // "connected", "listening", etc.
	IncomingData chan []byte
	OutgoingData chan []byte
}

// VirtualListener represents a listening socket
type VirtualListener struct {
	Addr         net.Addr
	Type         string // "tcp" or "udp"
	AcceptQueue  chan *VirtualConnection
}

// NewVirtualNetworkStack creates a new virtual network stack
func NewVirtualNetworkStack() (*VirtualNetworkStack, error) {
	return &VirtualNetworkStack{
		connections:      make(map[uint32]*VirtualConnection),
		listeningSockets: make(map[string]*VirtualListener),
		outgoingPackets:  make(chan []byte, 1000),
	}, nil
}

// SetLocalAddress sets the local WireGuard IP address
func (s *VirtualNetworkStack) SetLocalAddress(addr *net.IPNet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localIP = addr.IP
	s.localNet = addr
}

// CreateConnection creates a new virtual connection
func (s *VirtualNetworkStack) CreateConnection(connType string) (*VirtualConnection, error) {
	connID := atomic.AddUint32(&s.nextConnID, 1)
	
	conn := &VirtualConnection{
		ID:           connID,
		Type:         connType,
		State:        "created",
		IncomingData: make(chan []byte, 100),
		OutgoingData: make(chan []byte, 100),
	}

	s.mu.Lock()
	s.connections[connID] = conn
	s.mu.Unlock()

	// Start packet handler for this connection
	go s.handleConnectionPackets(conn)

	return conn, nil
}

// BindConnection binds a connection to a local address
func (s *VirtualNetworkStack) BindConnection(connID uint32, addr net.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, exists := s.connections[connID]
	if !exists {
		return fmt.Errorf("connection %d not found", connID)
	}

	conn.LocalAddr = addr
	return nil
}

// ListenConnection puts a connection in listening state
func (s *VirtualNetworkStack) ListenConnection(connID uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, exists := s.connections[connID]
	if !exists {
		return fmt.Errorf("connection %d not found", connID)
	}

	if conn.LocalAddr == nil {
		return fmt.Errorf("connection must be bound before listening")
	}

	listener := &VirtualListener{
		Addr:        conn.LocalAddr,
		Type:        conn.Type,
		AcceptQueue: make(chan *VirtualConnection, 10),
	}

	s.listeningSockets[conn.LocalAddr.String()] = listener
	conn.State = "listening"

	return nil
}

// ConnectConnection connects to a remote address
func (s *VirtualNetworkStack) ConnectConnection(connID uint32, remoteAddr net.Addr) error {
	s.mu.Lock()
	conn, exists := s.connections[connID]
	s.mu.Unlock()

	if !exists {
		return fmt.Errorf("connection %d not found", connID)
	}

	// Assign local address if not bound
	if conn.LocalAddr == nil {
		// Auto-assign ephemeral port
		localPort := 30000 + (connID % 30000)
		if conn.Type == "tcp" {
			conn.LocalAddr = &net.TCPAddr{IP: s.localIP, Port: int(localPort)}
		} else {
			conn.LocalAddr = &net.UDPAddr{IP: s.localIP, Port: int(localPort)}
		}
	}

	conn.RemoteAddr = remoteAddr
	conn.State = "connected"

	// Send SYN packet for TCP
	if conn.Type == "tcp" {
		synPacket := s.createTCPPacket(conn, nil, true, false, false)
		s.outgoingPackets <- synPacket
	}

	return nil
}

// SendData sends data on a connection
func (s *VirtualNetworkStack) SendData(connID uint32, data []byte) error {
	s.mu.RLock()
	conn, exists := s.connections[connID]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("connection %d not found", connID)
	}

	if conn.State != "connected" {
		return fmt.Errorf("connection not in connected state")
	}

	// Queue data for sending
	select {
	case conn.OutgoingData <- data:
		return nil
	default:
		return fmt.Errorf("outgoing buffer full")
	}
}

// ReceiveData receives data from a connection
func (s *VirtualNetworkStack) ReceiveData(connID uint32) ([]byte, error) {
	s.mu.RLock()
	conn, exists := s.connections[connID]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("connection %d not found", connID)
	}

	select {
	case data := <-conn.IncomingData:
		return data, nil
	default:
		return nil, fmt.Errorf("no data available")
	}
}

// AcceptConnection accepts a new connection on a listening socket
func (s *VirtualNetworkStack) AcceptConnection(listenAddr net.Addr) (*VirtualConnection, error) {
	s.mu.RLock()
	listener, exists := s.listeningSockets[listenAddr.String()]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no listener on %s", listenAddr.String())
	}

	select {
	case conn := <-listener.AcceptQueue:
		return conn, nil
	default:
		return nil, fmt.Errorf("no pending connections")
	}
}

// CloseConnection closes a virtual connection
func (s *VirtualNetworkStack) CloseConnection(connID uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, exists := s.connections[connID]
	if !exists {
		return fmt.Errorf("connection %d not found", connID)
	}

	// Send FIN packet for TCP
	if conn.Type == "tcp" && conn.State == "connected" {
		finPacket := s.createTCPPacket(conn, nil, false, false, true)
		s.outgoingPackets <- finPacket
	}

	close(conn.IncomingData)
	close(conn.OutgoingData)
	delete(s.connections, connID)

	// Remove from listening sockets if it was listening
	if conn.State == "listening" && conn.LocalAddr != nil {
		delete(s.listeningSockets, conn.LocalAddr.String())
	}

	return nil
}

// OutgoingPackets returns the channel for outgoing packets
func (s *VirtualNetworkStack) OutgoingPackets() <-chan []byte {
	return s.outgoingPackets
}

// DeliverIncomingPacket processes an incoming packet from WireGuard
func (s *VirtualNetworkStack) DeliverIncomingPacket(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too short")
	}

	// Parse IP header
	version := packet[0] >> 4
	if version != 4 {
		return fmt.Errorf("only IPv4 supported currently")
	}

	protocol := packet[9]
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	headerLen := int(packet[0]&0x0f) * 4
	if len(packet) < headerLen {
		return fmt.Errorf("invalid IP header length")
	}

	payload := packet[headerLen:]

	switch protocol {
	case 6: // TCP
		return s.handleIncomingTCP(srcIP, dstIP, payload)
	case 17: // UDP
		return s.handleIncomingUDP(srcIP, dstIP, payload)
	default:
		return fmt.Errorf("unsupported protocol: %d", protocol)
	}
}

// handleConnectionPackets handles outgoing packets for a connection
func (s *VirtualNetworkStack) handleConnectionPackets(conn *VirtualConnection) {
	for data := range conn.OutgoingData {
		var packet []byte
		if conn.Type == "tcp" {
			packet = s.createTCPPacket(conn, data, false, true, false)
		} else {
			packet = s.createUDPPacket(conn, data)
		}
		s.outgoingPackets <- packet
	}
}

// createTCPPacket creates a TCP/IP packet
func (s *VirtualNetworkStack) createTCPPacket(conn *VirtualConnection, data []byte, syn, ack, fin bool) []byte {
	// This is a simplified implementation
	// In production, you'd need proper TCP sequence numbers, checksums, etc.
	
	tcpAddr, _ := conn.LocalAddr.(*net.TCPAddr)
	remoteTCPAddr, _ := conn.RemoteAddr.(*net.TCPAddr)

	// IP header (20 bytes)
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // Version 4, header length 5 (20 bytes)
	ipHeader[1] = 0    // TOS
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(20+20+len(data))) // Total length
	binary.BigEndian.PutUint16(ipHeader[4:6], 0) // ID
	ipHeader[6] = 0x40 // Flags (Don't Fragment)
	ipHeader[8] = 64   // TTL
	ipHeader[9] = 6    // Protocol (TCP)
	// Checksum would go in bytes 10-11
	copy(ipHeader[12:16], tcpAddr.IP.To4())
	copy(ipHeader[16:20], remoteTCPAddr.IP.To4())

	// TCP header (20 bytes minimum)
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(tcpAddr.Port))
	binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(remoteTCPAddr.Port))
	// Sequence number, ACK number would go here
	tcpHeader[12] = 0x50 // Header length (5 * 4 = 20 bytes)
	
	// Flags
	flags := byte(0)
	if syn {
		flags |= 0x02
	}
	if ack {
		flags |= 0x10
	}
	if fin {
		flags |= 0x01
	}
	tcpHeader[13] = flags
	
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535) // Window size
	// Checksum would go in bytes 16-18

	// Combine all parts
	packet := make([]byte, 0, 40+len(data))
	packet = append(packet, ipHeader...)
	packet = append(packet, tcpHeader...)
	packet = append(packet, data...)

	return packet
}

// createUDPPacket creates a UDP/IP packet
func (s *VirtualNetworkStack) createUDPPacket(conn *VirtualConnection, data []byte) []byte {
	udpAddr, _ := conn.LocalAddr.(*net.UDPAddr)
	remoteUDPAddr, _ := conn.RemoteAddr.(*net.UDPAddr)

	// IP header (20 bytes)
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // Version 4, header length 5
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(20+8+len(data))) // Total length
	ipHeader[8] = 64  // TTL
	ipHeader[9] = 17  // Protocol (UDP)
	copy(ipHeader[12:16], udpAddr.IP.To4())
	copy(ipHeader[16:20], remoteUDPAddr.IP.To4())

	// UDP header (8 bytes)
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], uint16(udpAddr.Port))
	binary.BigEndian.PutUint16(udpHeader[2:4], uint16(remoteUDPAddr.Port))
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(8+len(data))) // Length

	// Combine all parts
	packet := make([]byte, 0, 28+len(data))
	packet = append(packet, ipHeader...)
	packet = append(packet, udpHeader...)
	packet = append(packet, data...)

	return packet
}

// handleIncomingTCP handles incoming TCP packets
func (s *VirtualNetworkStack) handleIncomingTCP(srcIP, dstIP net.IP, payload []byte) error {
	if len(payload) < 20 {
		return fmt.Errorf("TCP header too short")
	}

	srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	flags := payload[13]

	localAddr := &net.TCPAddr{IP: dstIP, Port: int(dstPort)}
	remoteAddr := &net.TCPAddr{IP: srcIP, Port: int(srcPort)}

	// Check if this is for a listening socket
	s.mu.RLock()
	listener, hasListener := s.listeningSockets[localAddr.String()]
	s.mu.RUnlock()

	if hasListener && (flags&0x02) != 0 { // SYN flag
		// Create new connection for incoming SYN
		newConn, _ := s.CreateConnection("tcp")
		newConn.LocalAddr = localAddr
		newConn.RemoteAddr = remoteAddr
		newConn.State = "connected"

		// Queue for accept
		select {
		case listener.AcceptQueue <- newConn:
		default:
			// Accept queue full
		}

		// Send SYN-ACK
		synAckPacket := s.createTCPPacket(newConn, nil, true, true, false)
		s.outgoingPackets <- synAckPacket
		return nil
	}

	// Find existing connection
	s.mu.RLock()
	var conn *VirtualConnection
	for _, c := range s.connections {
		if c.Type == "tcp" && 
		   c.LocalAddr != nil && c.LocalAddr.String() == localAddr.String() &&
		   c.RemoteAddr != nil && c.RemoteAddr.String() == remoteAddr.String() {
			conn = c
			break
		}
	}
	s.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("no connection found for TCP packet")
	}

	// Extract data after TCP header
	headerLen := int((payload[12]>>4)&0x0f) * 4
	if len(payload) > headerLen {
		data := payload[headerLen:]
		select {
		case conn.IncomingData <- data:
		default:
			// Buffer full
		}
	}

	return nil
}

// handleIncomingUDP handles incoming UDP packets
func (s *VirtualNetworkStack) handleIncomingUDP(srcIP, dstIP net.IP, payload []byte) error {
	if len(payload) < 8 {
		return fmt.Errorf("UDP header too short")
	}

	srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	
	localAddr := &net.UDPAddr{IP: dstIP, Port: int(dstPort)}
	remoteAddr := &net.UDPAddr{IP: srcIP, Port: int(srcPort)}

	// Find connection
	s.mu.RLock()
	var conn *VirtualConnection
	for _, c := range s.connections {
		if c.Type == "udp" && 
		   c.LocalAddr != nil && c.LocalAddr.String() == localAddr.String() {
			conn = c
			break
		}
	}
	s.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("no connection found for UDP packet")
	}

	// Update remote address for UDP (connectionless)
	conn.RemoteAddr = remoteAddr

	// Extract data
	data := payload[8:]
	select {
	case conn.IncomingData <- data:
	default:
		// Buffer full
	}

	return nil
}