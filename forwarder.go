package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
)

type PortForwarder struct {
	tunnel    *Tunnel
	msgChan   <-chan IPCMessage
	listeners map[int]net.Listener
	mutex     sync.RWMutex
}

func NewPortForwarder(tunnel *Tunnel, msgChan <-chan IPCMessage) *PortForwarder {
	return &PortForwarder{
		tunnel:    tunnel,
		msgChan:   msgChan,
		listeners: make(map[int]net.Listener),
	}
}

func (pf *PortForwarder) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			pf.closeAllListeners()
			return
		case msg := <-pf.msgChan:
			if msg.Type == "BIND" {
				if err := pf.handleBind(msg.Port); err != nil {
					logger.Errorf("Failed to handle bind for port %d: %v", msg.Port, err)
				}
			}
		}
	}
}

func (pf *PortForwarder) handleBind(port int) error {
	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	// Check if we're already listening on this port
	if _, exists := pf.listeners[port]; exists {
		return nil // Already listening
	}

	// Create a listener on the WireGuard IP
	// For now, listen on all interfaces since we don't have a proper WireGuard interface
	// In a full implementation, this would listen specifically on the WireGuard IP
	wgIP := pf.tunnel.ourIP.String()
	listenAddr := fmt.Sprintf("%s:%d", wgIP, port)

	logger.Debugf("Port forwarder: attempting to listen on %s", listenAddr)

	// Try to listen on the WireGuard IP - this will likely fail without a real interface
	// but it demonstrates the correct approach
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		// Fallback: listen on localhost for testing
		logger.Debugf("Port forwarder: failed to listen on WireGuard IP (%v), falling back to localhost", err)
		listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return fmt.Errorf("failed to create port forwarder listener: %w", err)
		}
		logger.Infof("Port forwarder: listening on 127.0.0.1:%d (fallback)", port)
	} else {
		logger.Infof("Port forwarder: successfully listening on %s", listenAddr)
	}

	pf.listeners[port] = listener

	// Start accepting connections in background
	go pf.acceptConnections(listener, port)

	return nil
}

func (pf *PortForwarder) acceptConnections(listener net.Listener, port int) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener was closed
			break
		}

		// Handle connection in background
		go pf.handleConnection(conn, port)
	}
}

func (pf *PortForwarder) handleConnection(wgConn net.Conn, port int) {
	defer wgConn.Close()

	// Connect to localhost port
	localConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		logger.Errorf("Failed to connect to localhost:%d: %v", port, err)
		return
	}
	defer localConn.Close()

	// Relay data bidirectionally
	go func() {
		io.Copy(localConn, wgConn)
		localConn.Close()
	}()

	io.Copy(wgConn, localConn)
}

func (pf *PortForwarder) closeAllListeners() {
	pf.mutex.Lock()
	defer pf.mutex.Unlock()

	for port, listener := range pf.listeners {
		listener.Close()
		delete(pf.listeners, port)
	}
}
