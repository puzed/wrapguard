package main

import (
	"context"
	"fmt"
	"net"

	"github.com/armon/go-socks5"
)

type SOCKS5Server struct {
	server   *socks5.Server
	listener net.Listener
	port     int
	tunnel   *Tunnel
}

func NewSOCKS5Server(tunnel *Tunnel) (*SOCKS5Server, error) {
	// Create SOCKS5 server with custom dialer that routes WireGuard IPs through the tunnel
	socksConfig := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			logger.Debugf("SOCKS5 dial request: %s %s", network, addr)

			// Parse the address to check if it's a WireGuard IP
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address format: %w", err)
			}

			// Check if this is a WireGuard IP that should be routed through the tunnel
			ip := net.ParseIP(host)
			if ip != nil && tunnel.IsWireGuardIP(ip) {
				logger.Debugf("Routing %s through WireGuard tunnel", addr)
				return tunnel.DialWireGuard(ctx, network, host, port)
			}

			// For non-WireGuard IPs, use normal dialing
			logger.Debugf("Using normal dial for %s", addr)
			dialer := &net.Dialer{}
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				logger.Debugf("SOCKS5 dial failed for %s: %v", addr, err)
			} else {
				logger.Debugf("SOCKS5 dial succeeded for %s", addr)
			}
			return conn, err
		},
	}

	server, err := socks5.New(socksConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 server: %w", err)
	}

	// Listen on localhost for SOCKS5 connections
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen for SOCKS5 connections: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	s := &SOCKS5Server{
		server:   server,
		listener: listener,
		port:     port,
		tunnel:   tunnel,
	}

	// Start serving in background
	go func() {
		if err := server.Serve(listener); err != nil {
			// Log error but don't crash - server might be shutting down
			logger.Debugf("SOCKS5 server stopped: %v", err)
		}
	}()

	return s, nil
}

func (s *SOCKS5Server) Port() int {
	return s.port
}

func (s *SOCKS5Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
