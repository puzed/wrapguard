package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type IPCMessage struct {
	Type   string `json:"type"` // "READY", "CONNECT", "BIND", and debug/transport events
	FD     int    `json:"fd"`
	Port   int    `json:"port"`
	Addr   string `json:"addr"`
	PID    int    `json:"pid"`
	Detail string `json:"detail"`
}

type IPCServer struct {
	listener   net.Listener
	socketPath string
	msgChan    chan IPCMessage
	mu         sync.Mutex
	nextSubID  int
	subs       map[int]chan IPCMessage
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
		subs:       make(map[int]chan IPCMessage),
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
			logger.Warnf("IPC failed to parse message: %v", err)
			continue
		}

		s.dispatchMessage(msg)
	}
}

func (s *IPCServer) dispatchMessage(msg IPCMessage) {
	select {
	case s.msgChan <- msg:
	default:
		logger.Warnf("IPC message channel full, dropping %s from pid %d", msg.Type, msg.PID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for id, ch := range s.subs {
		select {
		case ch <- msg:
		default:
			logger.Warnf("IPC subscriber %d channel full, dropping %s from pid %d", id, msg.Type, msg.PID)
		}
	}
}

func (s *IPCServer) SocketPath() string {
	return s.socketPath
}

func (s *IPCServer) MessageChan() <-chan IPCMessage {
	return s.msgChan
}

func (s *IPCServer) Subscribe() (int, <-chan IPCMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.nextSubID
	s.nextSubID++
	ch := make(chan IPCMessage, 32)
	s.subs[id] = ch

	return id, ch
}

func (s *IPCServer) Unsubscribe(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.subs[id]
	if !ok {
		return
	}
	delete(s.subs, id)
	close(ch)
}

func (s *IPCServer) WaitForMessageType(msgType string, timeout time.Duration) (IPCMessage, error) {
	subID, ch := s.Subscribe()
	defer s.Unsubscribe(subID)

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return IPCMessage{}, fmt.Errorf("ipc subscriber closed while waiting for %s", msgType)
			}
			if msg.Type == msgType {
				return msg, nil
			}
		case <-timer.C:
			return IPCMessage{}, fmt.Errorf("timed out waiting for IPC message type %s", msgType)
		}
	}
}

func (s *IPCServer) Close() error {
	if s.listener != nil {
		s.listener.Close()
	}

	s.mu.Lock()
	for id, ch := range s.subs {
		delete(s.subs, id)
		close(ch)
	}
	s.mu.Unlock()

	// Clean up socket file
	if s.socketPath != "" {
		os.Remove(s.socketPath)
	}

	return nil
}
