package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// IPCServer handles communication with the LD_PRELOAD library
type IPCServer struct {
	socketPath string
	listener   net.Listener
	netStack   *VirtualNetworkStack
	wgProxy    *WireGuardProxy
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

// IPCMessage represents a message between the main process and LD_PRELOAD library
type IPCMessage struct {
	Type     string          `json:"type"`
	ConnID   uint32          `json:"conn_id,omitempty"`
	SocketFD int             `json:"socket_fd,omitempty"`
	Domain   int             `json:"domain,omitempty"`
	SockType int             `json:"sock_type,omitempty"`
	Protocol int             `json:"protocol,omitempty"`
	Address  string          `json:"address,omitempty"`
	Port     int             `json:"port,omitempty"`
	Data     []byte          `json:"data,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// IPCResponse represents a response to an IPC message
type IPCResponse struct {
	Success bool   `json:"success"`
	ConnID  uint32 `json:"conn_id,omitempty"`
	Data    []byte `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

// NewIPCServer creates a new IPC server
func NewIPCServer(netStack *VirtualNetworkStack, wgProxy *WireGuardProxy) (*IPCServer, error) {
	// Create socket path in temp directory
	tmpDir := os.TempDir()
	socketPath := filepath.Join(tmpDir, fmt.Sprintf("wrapguard_%d.sock", os.Getpid()))

	return &IPCServer{
		socketPath: socketPath,
		netStack:   netStack,
		wgProxy:    wgProxy,
		stopChan:   make(chan struct{}),
	}, nil
}

// SocketPath returns the Unix socket path
func (s *IPCServer) SocketPath() string {
	return s.socketPath
}

// Start starts the IPC server
func (s *IPCServer) Start() error {
	// Remove any existing socket
	os.Remove(s.socketPath)

	// Create Unix domain socket
	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to create Unix socket: %w", err)
	}
	s.listener = listener

	// Start accepting connections
	s.wg.Add(1)
	go s.acceptConnections()

	return nil
}

// Stop stops the IPC server
func (s *IPCServer) Stop() error {
	close(s.stopChan)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	os.Remove(s.socketPath)
	return nil
}

// acceptConnections accepts incoming IPC connections
func (s *IPCServer) acceptConnections() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
				// Log error and continue
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single IPC connection
func (s *IPCServer) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	for {
		var msg IPCMessage
		if err := decoder.Decode(&msg); err != nil {
			return
		}

		response := s.handleMessage(&msg)
		if err := encoder.Encode(response); err != nil {
			return
		}
	}
}

// handleMessage processes an IPC message and returns a response
func (s *IPCServer) handleMessage(msg *IPCMessage) *IPCResponse {
	switch msg.Type {
	case "socket":
		return s.handleSocket(msg)
	case "bind":
		return s.handleBind(msg)
	case "listen":
		return s.handleListen(msg)
	case "accept":
		return s.handleAccept(msg)
	case "connect":
		return s.handleConnect(msg)
	case "send":
		return s.handleSend(msg)
	case "recv":
		return s.handleRecv(msg)
	case "close":
		return s.handleClose(msg)
	default:
		return &IPCResponse{
			Success: false,
			Error:   fmt.Sprintf("unknown message type: %s", msg.Type),
		}
	}
}

// handleSocket handles socket creation
func (s *IPCServer) handleSocket(msg *IPCMessage) *IPCResponse {
	// Only support AF_INET (2) and SOCK_STREAM (1) or SOCK_DGRAM (2)
	if msg.Domain != 2 {
		return &IPCResponse{
			Success: false,
			Error:   "only AF_INET supported",
		}
	}

	var connType string
	switch msg.SockType {
	case 1: // SOCK_STREAM
		connType = "tcp"
	case 2: // SOCK_DGRAM
		connType = "udp"
	default:
		return &IPCResponse{
			Success: false,
			Error:   "unsupported socket type",
		}
	}

	conn, err := s.netStack.CreateConnection(connType)
	if err != nil {
		return &IPCResponse{
			Success: false,
			Error:   err.Error(),
		}
	}

	return &IPCResponse{
		Success: true,
		ConnID:  conn.ID,
	}
}

// handleBind handles bind requests
func (s *IPCServer) handleBind(msg *IPCMessage) *IPCResponse {
	var addr net.Addr
	if msg.Address == "" || msg.Address == "0.0.0.0" {
		// Use WireGuard interface IP
		if s.wgProxy.config.Interface.Address != nil {
			msg.Address = s.wgProxy.config.Interface.Address.IP.String()
		}
	}

	conn, _ := s.getConnection(msg.ConnID)
	if conn == nil {
		return &IPCResponse{
			Success: false,
			Error:   "connection not found",
		}
	}

	if conn.Type == "tcp" {
		addr = &net.TCPAddr{
			IP:   net.ParseIP(msg.Address),
			Port: msg.Port,
		}
	} else {
		addr = &net.UDPAddr{
			IP:   net.ParseIP(msg.Address),
			Port: msg.Port,
		}
	}

	if err := s.netStack.BindConnection(msg.ConnID, addr); err != nil {
		return &IPCResponse{
			Success: false,
			Error:   err.Error(),
		}
	}

	return &IPCResponse{Success: true}
}

// handleListen handles listen requests
func (s *IPCServer) handleListen(msg *IPCMessage) *IPCResponse {
	if err := s.netStack.ListenConnection(msg.ConnID); err != nil {
		return &IPCResponse{
			Success: false,
			Error:   err.Error(),
		}
	}

	return &IPCResponse{Success: true}
}

// handleAccept handles accept requests
func (s *IPCServer) handleAccept(msg *IPCMessage) *IPCResponse {
	conn, _ := s.getConnection(msg.ConnID)
	if conn == nil {
		return &IPCResponse{
			Success: false,
			Error:   "connection not found",
		}
	}

	// Try to accept with timeout
	for i := 0; i < 100; i++ { // 10 second timeout
		newConn, err := s.netStack.AcceptConnection(conn.LocalAddr)
		if err == nil {
			return &IPCResponse{
				Success: true,
				ConnID:  newConn.ID,
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	return &IPCResponse{
		Success: false,
		Error:   "accept timeout",
	}
}

// handleConnect handles connect requests
func (s *IPCServer) handleConnect(msg *IPCMessage) *IPCResponse {
	conn, _ := s.getConnection(msg.ConnID)
	if conn == nil {
		return &IPCResponse{
			Success: false,
			Error:   "connection not found",
		}
	}

	var remoteAddr net.Addr
	if conn.Type == "tcp" {
		remoteAddr = &net.TCPAddr{
			IP:   net.ParseIP(msg.Address),
			Port: msg.Port,
		}
	} else {
		remoteAddr = &net.UDPAddr{
			IP:   net.ParseIP(msg.Address),
			Port: msg.Port,
		}
	}

	if err := s.netStack.ConnectConnection(msg.ConnID, remoteAddr); err != nil {
		return &IPCResponse{
			Success: false,
			Error:   err.Error(),
		}
	}

	// Set local address in network stack
	if s.wgProxy.config.Interface.Address != nil {
		s.netStack.SetLocalAddress(s.wgProxy.config.Interface.Address)
	}

	return &IPCResponse{Success: true}
}

// handleSend handles send requests
func (s *IPCServer) handleSend(msg *IPCMessage) *IPCResponse {
	if err := s.netStack.SendData(msg.ConnID, msg.Data); err != nil {
		return &IPCResponse{
			Success: false,
			Error:   err.Error(),
		}
	}

	return &IPCResponse{
		Success: true,
		Data:    []byte{}, // Return number of bytes sent
	}
}

// handleRecv handles receive requests
func (s *IPCServer) handleRecv(msg *IPCMessage) *IPCResponse {
	data, err := s.netStack.ReceiveData(msg.ConnID)
	if err != nil {
		// Try waiting a bit for data
		for i := 0; i < 10; i++ {
			time.Sleep(100 * time.Millisecond)
			data, err = s.netStack.ReceiveData(msg.ConnID)
			if err == nil {
				break
			}
		}
		
		if err != nil {
			return &IPCResponse{
				Success: false,
				Error:   err.Error(),
			}
		}
	}

	return &IPCResponse{
		Success: true,
		Data:    data,
	}
}

// handleClose handles close requests
func (s *IPCServer) handleClose(msg *IPCMessage) *IPCResponse {
	if err := s.netStack.CloseConnection(msg.ConnID); err != nil {
		return &IPCResponse{
			Success: false,
			Error:   err.Error(),
		}
	}

	return &IPCResponse{Success: true}
}

// getConnection retrieves a connection by ID
func (s *IPCServer) getConnection(connID uint32) (*VirtualConnection, bool) {
	s.netStack.mu.RLock()
	defer s.netStack.mu.RUnlock()
	conn, exists := s.netStack.connections[connID]
	return conn, exists
}

// Helper to read length-prefixed messages
func readMessage(conn net.Conn) ([]byte, error) {
	// Read 4-byte length prefix
	lengthBuf := make([]byte, 4)
	if _, err := conn.Read(lengthBuf); err != nil {
		return nil, err
	}
	
	length := binary.BigEndian.Uint32(lengthBuf)
	if length > 1024*1024 { // 1MB max message size
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}
	
	// Read message data
	data := make([]byte, length)
	if _, err := conn.Read(data); err != nil {
		return nil, err
	}
	
	return data, nil
}

// Helper to write length-prefixed messages
func writeMessage(conn net.Conn, data []byte) error {
	// Write 4-byte length prefix
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))
	
	if _, err := conn.Write(lengthBuf); err != nil {
		return err
	}
	
	// Write message data
	if _, err := conn.Write(data); err != nil {
		return err
	}
	
	return nil
}