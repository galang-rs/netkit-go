package cgnat

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// HolePunchState represents the state of a hole-punch attempt.
type HolePunchState int

const (
	HolePunchIdle      HolePunchState = iota
	HolePunchPunching                 // Sending probe packets
	HolePunchConnected                // Hole established
	HolePunchFailed                   // Timed out or error
)

func (s HolePunchState) String() string {
	switch s {
	case HolePunchIdle:
		return "Idle"
	case HolePunchPunching:
		return "Punching"
	case HolePunchConnected:
		return "Connected"
	case HolePunchFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// HolePunchConfig configures hole-punch behavior.
type HolePunchConfig struct {
	// PeerAddr is the peer's public address (from signaling).
	PeerAddr *net.UDPAddr
	// LocalPort is the local port to punch from (0 = auto).
	LocalPort int
	// Timeout for the hole-punch attempt.
	Timeout time.Duration
	// KeepAlive interval to maintain the NAT mapping.
	KeepAlive time.Duration
	// ProbeInterval between punch packets during establishment.
	ProbeInterval time.Duration
	// MaxRetries before giving up.
	MaxRetries int
}

// DefaultHolePunchConfig returns sensible defaults.
func DefaultHolePunchConfig(peerAddr *net.UDPAddr) *HolePunchConfig {
	return &HolePunchConfig{
		PeerAddr:      peerAddr,
		LocalPort:     0,
		Timeout:       10 * time.Second,
		KeepAlive:     20 * time.Second,
		ProbeInterval: 100 * time.Millisecond,
		MaxRetries:    100,
	}
}

// HolePuncher performs UDP hole-punching to traverse NAT.
type HolePuncher struct {
	conn   *net.UDPConn
	state  atomic.Int32
	mu     sync.Mutex
	onData func(data []byte, from *net.UDPAddr)
}

// NewHolePuncher creates a new hole-puncher.
func NewHolePuncher() *HolePuncher {
	return &HolePuncher{}
}

// Punch attempts to establish a UDP hole-punch with a peer.
// Returns the connection if successful.
func (hp *HolePuncher) Punch(ctx context.Context, cfg *HolePunchConfig) (*net.UDPConn, error) {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	hp.state.Store(int32(HolePunchPunching))

	// Create local socket
	localAddr := &net.UDPAddr{IP: net.IPv4zero, Port: cfg.LocalPort}
	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		hp.state.Store(int32(HolePunchFailed))
		return nil, fmt.Errorf("listen UDP: %w", err)
	}
	hp.conn = conn

	// Probe packet — small magic bytes to identify hole-punch probes
	probePayload := []byte("NKPUNCH\x00")

	// Start punching
	done := make(chan struct{})
	var punchErr error

	go func() {
		defer close(done)
		buf := make([]byte, 256)

		for i := 0; i < cfg.MaxRetries; i++ {
			select {
			case <-ctx.Done():
				punchErr = ctx.Err()
				return
			default:
			}

			// Send probe to peer
			_, err := conn.WriteTo(probePayload, cfg.PeerAddr)
			if err != nil {
				punchErr = fmt.Errorf("send probe: %w", err)
				return
			}

			// Wait for response
			conn.SetReadDeadline(time.Now().Add(cfg.ProbeInterval))
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue // Timeout, try again
			}

			// Check if it's a probe response from peer
			if n >= len(probePayload) && string(buf[:8]) == "NKPUNCH\x00" {
				// Hole established! Send confirmation
				conn.WriteTo([]byte("NKACK\x00"), from)
				hp.state.Store(int32(HolePunchConnected))
				return
			}
		}
		punchErr = fmt.Errorf("hole-punch timed out after %d retries", cfg.MaxRetries)
	}()

	// Wait with overall timeout
	select {
	case <-done:
	case <-ctx.Done():
		punchErr = ctx.Err()
	case <-time.After(cfg.Timeout):
		punchErr = fmt.Errorf("hole-punch timeout")
	}

	if punchErr != nil {
		hp.state.Store(int32(HolePunchFailed))
		conn.Close()
		return nil, punchErr
	}

	// Clear deadline for normal operation
	conn.SetReadDeadline(time.Time{})

	// Start keepalive goroutine
	go hp.keepAlive(ctx, conn, cfg.PeerAddr, cfg.KeepAlive)

	return conn, nil
}

// State returns the current hole-punch state.
func (hp *HolePuncher) State() HolePunchState {
	return HolePunchState(hp.state.Load())
}

// Close closes the hole-punched connection.
func (hp *HolePuncher) Close() error {
	hp.state.Store(int32(HolePunchIdle))
	if hp.conn != nil {
		return hp.conn.Close()
	}
	return nil
}

// keepAlive sends periodic keepalive probes to maintain NAT mapping.
func (hp *HolePuncher) keepAlive(ctx context.Context, conn *net.UDPConn, peer *net.UDPAddr, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	keepalivePayload := []byte("NKKA\x00") // keepalive marker

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if HolePunchState(hp.state.Load()) != HolePunchConnected {
				return
			}
			_, err := conn.WriteTo(keepalivePayload, peer)
			if err != nil {
				return
			}
		}
	}
}

// TCPHolePunch attempts TCP Simultaneous Open (less reliable, fallback).
func TCPHolePunch(ctx context.Context, localPort int, peerAddr string, timeout time.Duration) (net.Conn, error) {
	localAddr := &net.TCPAddr{IP: net.IPv4zero, Port: localPort}

	dialer := net.Dialer{
		LocalAddr: localAddr,
		Timeout:   timeout,
		Control:   reusePortControl, // SO_REUSEADDR/SO_REUSEPORT
	}

	// Simultaneous Open: both sides dial each other at the same time
	// This works if both sides start within the TCP handshake timeout
	var conn net.Conn
	var err error

	retryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		select {
		case <-retryCtx.Done():
			if conn != nil {
				return conn, nil
			}
			return nil, fmt.Errorf("TCP hole-punch timeout: %w", err)
		default:
		}

		conn, err = dialer.DialContext(retryCtx, "tcp", peerAddr)
		if err == nil {
			return conn, nil
		}

		time.Sleep(200 * time.Millisecond)
	}
}
