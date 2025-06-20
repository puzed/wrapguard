package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

type IPCMessage struct {
	Type string `json:"type"` // "CONNECT" or "BIND"
	FD   int    `json:"fd"`
	Port int    `json:"port"`
	Addr string `json:"addr"`
}

type IPCServer struct {
	listener   net.Listener
	socketPath string
	msgChan    chan IPCMessage
}

func NewIPCServer() (*IPCServer, error) {
	// Create socket path in temp directory
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("wrapguard-%d.sock", os.Getpid()))

	// Remove existing socket if it exists
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPC socket: %w", err)
	}

	server := &IPCServer{
		listener:   listener,
		socketPath: socketPath,
		msgChan:    make(chan IPCMessage, 100),
	}

	// Start accepting connections
	go server.acceptConnections()

	return server, nil
}

func (s *IPCServer) acceptConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Server is shutting down
			break
		}

		// Handle connection in background
		go s.handleConnection(conn)
	}
}

func (s *IPCServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()

		var msg IPCMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			fmt.Printf("IPC: Failed to parse message: %v\n", err)
			continue
		}

		// Send message to channel (non-blocking)
		select {
		case s.msgChan <- msg:
		default:
			fmt.Printf("IPC: Message channel full, dropping message\n")
		}
	}
}

func (s *IPCServer) SocketPath() string {
	return s.socketPath
}

func (s *IPCServer) MessageChan() <-chan IPCMessage {
	return s.msgChan
}

func (s *IPCServer) Close() error {
	if s.listener != nil {
		s.listener.Close()
	}

	// Clean up socket file
	if s.socketPath != "" {
		os.Remove(s.socketPath)
	}

	return nil
}
