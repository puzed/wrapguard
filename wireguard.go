package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// WireGuardProxy manages the WireGuard connection and packet routing
type WireGuardProxy struct {
	config   *WireGuardConfig
	device   *device.Device
	memTun   *MemoryTUN
	netStack *VirtualNetworkStack
	udpConn  *net.UDPConn
	logger   *device.Logger
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewWireGuardProxy creates a new WireGuard proxy
func NewWireGuardProxy(config *WireGuardConfig, netStack *VirtualNetworkStack, verbose bool) (*WireGuardProxy, error) {
	// Create logger
	var logger *device.Logger
	if verbose {
		logger = &device.Logger{
			Verbosef: func(format string, args ...interface{}) {
				log.Printf("[WireGuard] "+format, args...)
			},
			Errorf: func(format string, args ...interface{}) {
				log.Printf("[WireGuard ERROR] "+format, args...)
			},
		}
	} else {
		logger = &device.Logger{
			Verbosef: func(format string, args ...interface{}) {
				// Suppress verbose messages in quiet mode
			},
			Errorf: func(format string, args ...interface{}) {
				log.Printf("[WireGuard ERROR] "+format, args...)
			},
		}
	}

	// Create memory TUN
	memTun := NewMemoryTUN("wg0", config.Interface.MTU)

	// Create UDP socket for WireGuard
	listenAddr := fmt.Sprintf(":%d", config.Interface.ListenPort)
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}

	// Create WireGuard device
	device := device.NewDevice(memTun, conn.NewDefaultBind(), logger)

	// Configure the device
	if err := configureDevice(device, config); err != nil {
		device.Close()
		udpConn.Close()
		return nil, fmt.Errorf("failed to configure device: %w", err)
	}

	return &WireGuardProxy{
		config:   config,
		device:   device,
		memTun:   memTun,
		netStack: netStack,
		udpConn:  udpConn,
		logger:   logger,
		stopChan: make(chan struct{}),
	}, nil
}

// Start starts the WireGuard proxy
func (w *WireGuardProxy) Start() error {
	// Bring up the device
	w.device.Up()
	w.memTun.SendUp()

	// Start packet routing goroutines
	w.wg.Add(2)
	go w.routeIncomingPackets()
	go w.routeOutgoingPackets()

	return nil
}

// Stop stops the WireGuard proxy
func (w *WireGuardProxy) Stop() error {
	close(w.stopChan)
	w.wg.Wait()

	w.device.Down()
	w.device.Close()
	w.udpConn.Close()
	w.memTun.Close()

	return nil
}

// routeIncomingPackets routes packets from WireGuard to the virtual network stack
func (w *WireGuardProxy) routeIncomingPackets() {
	defer w.wg.Done()

	for {
		select {
		case <-w.stopChan:
			return
		default:
			// Read decrypted packet from WireGuard
			packet, err := w.memTun.ReadOutbound()
			if err != nil {
				if err.Error() != "EOF" {
					w.logger.Errorf("Failed to read from TUN: %v", err)
				}
				continue
			}

			// Route packet to virtual network stack
			if err := w.netStack.DeliverIncomingPacket(packet); err != nil {
				w.logger.Errorf("Failed to deliver incoming packet: %v", err)
			}
		}
	}
}

// routeOutgoingPackets routes packets from the virtual network stack to WireGuard
func (w *WireGuardProxy) routeOutgoingPackets() {
	defer w.wg.Done()

	for {
		select {
		case <-w.stopChan:
			return
		case packet := <-w.netStack.OutgoingPackets():
			// Send packet to WireGuard for encryption
			if err := w.memTun.InjectInbound(packet); err != nil {
				w.logger.Errorf("Failed to inject packet to WireGuard: %v", err)
			}
		}
	}
}

// SendPacket sends a packet through the WireGuard tunnel
func (w *WireGuardProxy) SendPacket(packet []byte) error {
	return w.memTun.InjectInbound(packet)
}

// configureDevice configures the WireGuard device with the provided configuration
func configureDevice(dev *device.Device, config *WireGuardConfig) error {
	// Decode private key
	privateKeyBytes, err := base64.StdEncoding.DecodeString(config.Interface.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to decode private key: %w", err)
	}

	// Build device configuration with hex-encoded key
	deviceConfig := fmt.Sprintf("private_key=%s\n", hex.EncodeToString(privateKeyBytes))

	// Add peers
	for _, peer := range config.Peers {
		publicKeyBytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to decode public key: %w", err)
		}

		deviceConfig += fmt.Sprintf("public_key=%s\n", hex.EncodeToString(publicKeyBytes))

		if peer.Endpoint != nil {
			// Convert to netip.AddrPort
			ip, err := netip.ParseAddr(peer.Endpoint.IP.String())
			if err != nil {
				return fmt.Errorf("failed to parse endpoint IP: %w", err)
			}
			endpoint := netip.AddrPortFrom(ip, uint16(peer.Endpoint.Port))
			deviceConfig += fmt.Sprintf("endpoint=%s\n", endpoint.String())
		}

		for _, allowedIP := range peer.AllowedIPs {
			ones, _ := allowedIP.Mask.Size()
			ip, err := netip.ParseAddr(allowedIP.IP.String())
			if err != nil {
				return fmt.Errorf("failed to parse allowed IP: %w", err)
			}
			prefix := netip.PrefixFrom(ip, ones)
			deviceConfig += fmt.Sprintf("allowed_ip=%s\n", prefix.String())
		}

		if peer.PersistentKeepalive > 0 {
			deviceConfig += fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
		}

		if peer.PresharedKey != "" {
			presharedKeyBytes, err := base64.StdEncoding.DecodeString(peer.PresharedKey)
			if err != nil {
				return fmt.Errorf("failed to decode preshared key: %w", err)
			}
			deviceConfig += fmt.Sprintf("preshared_key=%s\n", hex.EncodeToString(presharedKeyBytes))
		}
	}

	// Apply configuration
	reader := strings.NewReader(deviceConfig)
	if err := dev.IpcSetOperation(bufio.NewReader(reader)); err != nil {
		return fmt.Errorf("failed to configure device: %w", err)
	}

	return nil
}
