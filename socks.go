package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/armon/go-socks5"
)

type SOCKS5Server struct {
	server   *socks5.Server
	listener net.Listener
	port     int
	tunnel   *Tunnel
	dials    chan string
	wg       sync.WaitGroup
}

func buildSOCKS5Dial(tunnel *Tunnel, socksPort int, baseDial func(context.Context, string, string) (net.Conn, error), onDial func(string, string)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if onDial != nil {
			onDial(network, addr)
		}
		logger.Debugf("SOCKS5 dial request: %s %s", network, addr)

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address format: %w", err)
		}

		ip := net.ParseIP(host)
		if ip != nil && ip.IsLoopback() {
			portNum, _ := strconv.Atoi(port)
			if portNum == socksPort {
				return nil, fmt.Errorf("refusing recursive SOCKS dial to localhost:%d", socksPort)
			}
			return baseDial(ctx, network, addr)
		}

		if tunnel != nil && tunnel.router != nil && ip != nil {
			portNum, _ := strconv.Atoi(port)
			peer, peerIdx := tunnel.router.FindPeerForDestination(ip, portNum, normalizeNetworkProtocol(network))
			if peer != nil {
				logger.Debugf("Routing %s through WireGuard tunnel via peer %d (endpoint: %s)", addr, peerIdx, peer.Endpoint)
				return tunnel.DialWireGuard(ctx, network, host, port)
			}
		}

		logger.Debugf("Using normal dial for %s", addr)
		conn, err := baseDial(ctx, network, addr)
		if err != nil {
			logger.Debugf("SOCKS5 dial failed for %s: %v", addr, err)
		} else {
			logger.Debugf("SOCKS5 dial succeeded for %s", addr)
		}
		return conn, err
	}
}

func NewSOCKS5Server(tunnel *Tunnel) (*SOCKS5Server, error) {
	if tunnel == nil {
		return nil, fmt.Errorf("tunnel is required")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen for SOCKS5 connections: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	baseDialer := (&net.Dialer{}).DialContext

	s := &SOCKS5Server{
		listener: listener,
		port:     port,
		tunnel:   tunnel,
		dials:    make(chan string, 32),
	}
	socksConfig := &socks5.Config{}
	socksConfig.Dial = buildSOCKS5Dial(tunnel, port, baseDialer, func(_ string, addr string) {
		select {
		case s.dials <- addr:
		default:
		}
	})
	server, err := socks5.New(socksConfig)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("failed to create SOCKS5 server: %w", err)
	}
	s.server = server

	// Start serving in background
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
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

func (s *SOCKS5Server) WaitForDial(addr string, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case got := <-s.dials:
			if got == addr {
				return nil
			}
		case <-timer.C:
			return fmt.Errorf("timed out waiting for SOCKS dial to %s", addr)
		}
	}
}

func (s *SOCKS5Server) Close() error {
	if s.listener != nil {
		err := s.listener.Close()
		s.wg.Wait()
		return err
	}
	return nil
}
