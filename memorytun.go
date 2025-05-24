package main

import (
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// MemoryTUN implements a memory-based TUN device that doesn't require kernel interfaces
type MemoryTUN struct {
	name      string
	mtu       int
	closed    chan struct{}
	events    chan tun.Event
	inbound   chan []byte // Packets from WireGuard to applications
	outbound  chan []byte // Packets from applications to WireGuard
	closeOnce sync.Once
	mu        sync.Mutex
}

// NewMemoryTUN creates a new memory-based TUN device
func NewMemoryTUN(name string, mtu int) *MemoryTUN {
	return &MemoryTUN{
		name:     name,
		mtu:      mtu,
		closed:   make(chan struct{}),
		events:   make(chan tun.Event, 10),
		inbound:  make(chan []byte, 1000),
		outbound: make(chan []byte, 1000),
	}
}

// Name returns the name of the TUN device
func (t *MemoryTUN) Name() (string, error) {
	return t.name, nil
}

// File returns a nil file descriptor as we don't use real files
func (t *MemoryTUN) File() *os.File {
	return nil
}

// Events returns the event channel
func (t *MemoryTUN) Events() <-chan tun.Event {
	return t.events
}

// Read reads one or more packets from the TUN device (packets coming from applications)
// On a successful read it returns the number of packets read, and sets
// packet lengths within the sizes slice.
func (t *MemoryTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) {
		return 0, errors.New("invalid buffer or sizes slice")
	}

	packetsRead := 0
	for i := range bufs {
		select {
		case <-t.closed:
			if packetsRead == 0 {
				return 0, io.EOF
			}
			return packetsRead, nil
		case packet := <-t.outbound:
			if len(packet) > len(bufs[i])-offset {
				return packetsRead, errors.New("packet too large for buffer")
			}
			copy(bufs[i][offset:], packet)
			sizes[i] = len(packet)
			packetsRead++
		default:
			// No more packets available
			if packetsRead == 0 {
				// Block for at least one packet
				select {
				case <-t.closed:
					return 0, io.EOF
				case packet := <-t.outbound:
					if len(packet) > len(bufs[i])-offset {
						return 0, errors.New("packet too large for buffer")
					}
					copy(bufs[i][offset:], packet)
					sizes[i] = len(packet)
					return 1, nil
				}
			}
			return packetsRead, nil
		}
	}
	return packetsRead, nil
}

// Write writes one or more packets to the TUN device (packets going to applications)
// On a successful write it returns the number of packets written.
func (t *MemoryTUN) Write(bufs [][]byte, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}

	packetsWritten := 0
	for _, buf := range bufs {
		if offset >= len(buf) {
			continue
		}

		packet := make([]byte, len(buf)-offset)
		copy(packet, buf[offset:])

		select {
		case <-t.closed:
			if packetsWritten == 0 {
				return 0, io.EOF
			}
			return packetsWritten, nil
		case t.inbound <- packet:
			packetsWritten++
		default:
			// Drop packet if buffer is full but count as written
			packetsWritten++
		}
	}
	return packetsWritten, nil
}

// MTU returns the MTU of the TUN device
func (t *MemoryTUN) MTU() (int, error) {
	return t.mtu, nil
}

// Close closes the TUN device
func (t *MemoryTUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

// BatchSize returns the preferred/max number of packets that can be read or
// written in a single read/write call.
func (t *MemoryTUN) BatchSize() int {
	return 128 // Allow batching up to 128 packets
}

// InjectInbound injects a packet as if it came from the network (for sending to WireGuard)
func (t *MemoryTUN) InjectInbound(packet []byte) error {
	select {
	case <-t.closed:
		return io.EOF
	case t.outbound <- packet:
		return nil
	case <-time.After(100 * time.Millisecond):
		return errors.New("timeout injecting packet")
	}
}

// ReadOutbound reads a packet that WireGuard wants to send to the network
func (t *MemoryTUN) ReadOutbound() ([]byte, error) {
	select {
	case <-t.closed:
		return nil, io.EOF
	case packet := <-t.inbound:
		return packet, nil
	}
}

// SendUp sends the TUN up event
func (t *MemoryTUN) SendUp() {
	select {
	case t.events <- tun.EventUp:
	default:
	}
}

// SendDown sends the TUN down event
func (t *MemoryTUN) SendDown() {
	select {
	case t.events <- tun.EventDown:
	default:
	}
}
