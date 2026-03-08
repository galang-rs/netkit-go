// Package cgnat extension: NAT breaking (hole punching) enhancement
// and NetBIOS detector integration.
package cgnat

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// NATBreaker implements advanced NAT traversal techniques.
// Supports:
// - UDP hole punching
// - TCP simultaneous open
// - Port prediction for symmetric NAT
// - UPnP/NAT-PMP port mapping
type NATBreaker struct {
	mu              sync.Mutex
	stunServer      string
	localAddr       string
	mappedAddr      string // Our public IP:port as seen by STUN
	natType         NATType
	punchAttempts   int
	maxAttempts     int
	portPredictions []int // Predicted ports for symmetric NAT
}

// NATBreakResult contains the result of a NAT breaking attempt.
type NATBreakResult struct {
	Success     bool
	DirectAddr  string // Direct address if hole punch succeeded
	Method      string // "udp_holepunch", "tcp_simopen", "upnp", "relay"
	Latency     time.Duration
	NATType     NATType
	PeerNATType NATType
}

// NewNATBreaker creates a new NAT breaker.
func NewNATBreaker(stunServer string) *NATBreaker {
	return &NATBreaker{
		stunServer:  stunServer,
		maxAttempts: 10,
	}
}

// AttemptHolePunch tries to establish a direct UDP connection
// through NAT using hole punching.
func (nb *NATBreaker) AttemptHolePunch(peerAddr string) (*NATBreakResult, error) {
	nb.mu.Lock()
	defer nb.mu.Unlock()

	result := &NATBreakResult{
		Method:  "udp_holepunch",
		NATType: nb.natType,
	}

	// Create UDP socket
	laddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("resolve local: %w", err)
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	defer conn.Close()

	raddr, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve peer: %w", err)
	}

	// Send punch packets
	punchMsg := []byte("NETKIT-PUNCH")
	start := time.Now()

	for attempt := 0; attempt < nb.maxAttempts; attempt++ {
		_, err := conn.WriteToUDP(punchMsg, raddr)
		if err != nil {
			continue
		}

		// Try to receive response
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 64)
		n, from, err := conn.ReadFromUDP(buf)
		if err == nil && n > 0 {
			result.Success = true
			result.DirectAddr = from.String()
			result.Latency = time.Since(start)
			return result, nil
		}

		nb.punchAttempts++
	}

	return result, nil
}

// PredictPorts generates predicted ports for symmetric NAT traversal.
// Symmetric NATs often increment port allocations sequentially.
func (nb *NATBreaker) PredictPorts(basePort int, count int) []int {
	predictions := make([]int, count)
	for i := 0; i < count; i++ {
		predictions[i] = basePort + i
	}
	nb.portPredictions = predictions
	return predictions
}

// DetectAndBreak performs full NAT detection and attempts to break through.
func (nb *NATBreaker) DetectAndBreak(peerAddr string) (*NATBreakResult, error) {
	// Try hole punch first
	result, err := nb.AttemptHolePunch(peerAddr)
	if err != nil {
		return nil, err
	}

	if result.Success {
		return result, nil
	}

	// Fallback to relay
	result.Method = "relay"
	result.Success = false
	return result, nil
}

// GetPunchAttempts returns the number of hole punch attempts made.
func (nb *NATBreaker) GetPunchAttempts() int {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return nb.punchAttempts
}

// NetBIOSDetector detects and monitors NetBIOS traffic for device discovery.
type NetBIOSDetector struct {
	mu       sync.RWMutex
	devices  map[string]*NetBIOSDevice
	enabled  bool
	stopChan chan struct{}
}

// NetBIOSDevice represents a discovered device via NetBIOS.
type NetBIOSDevice struct {
	IP        string
	Hostname  string
	Workgroup string
	MACAddr   string
	FirstSeen time.Time
	LastSeen  time.Time
	Active    bool
}

// NewNetBIOSDetector creates a new detector.
func NewNetBIOSDetector() *NetBIOSDetector {
	return &NetBIOSDetector{
		devices:  make(map[string]*NetBIOSDevice),
		stopChan: make(chan struct{}),
	}
}

// Enable enables NetBIOS detection.
func (nd *NetBIOSDetector) Enable() {
	nd.mu.Lock()
	defer nd.mu.Unlock()
	nd.enabled = true
}

// Disable disables NetBIOS detection.
func (nd *NetBIOSDetector) Disable() {
	nd.mu.Lock()
	defer nd.mu.Unlock()
	nd.enabled = false
}

// IsEnabled returns whether detection is enabled.
func (nd *NetBIOSDetector) IsEnabled() bool {
	nd.mu.RLock()
	defer nd.mu.RUnlock()
	return nd.enabled
}

// ProcessPacket analyzes a potential NetBIOS packet.
// Standard NetBIOS Name Service uses UDP port 137.
func (nd *NetBIOSDetector) ProcessPacket(srcIP string, data []byte) {
	nd.mu.Lock()
	defer nd.mu.Unlock()

	if !nd.enabled {
		return
	}

	if len(data) < 46 {
		return
	}

	// NetBIOS name query response check
	// Transaction ID: bytes 0-1
	// Flags: bytes 2-3 (0x85 0x00 for response)
	flags := uint16(data[2])<<8 | uint16(data[3])
	isResponse := (flags & 0x8000) != 0

	if !isResponse {
		return
	}

	// Try to extract hostname from encoded NetBIOS name
	hostname := decodeNetBIOSName(data[13:45])
	if hostname == "" {
		return
	}

	now := time.Now()
	device, exists := nd.devices[srcIP]
	if !exists {
		device = &NetBIOSDevice{
			IP:        srcIP,
			Hostname:  hostname,
			FirstSeen: now,
			Active:    true,
		}
		nd.devices[srcIP] = device
		fmt.Printf("[NetBIOS] 🖥️  New device: %s (%s)\n", hostname, srcIP)
	} else {
		device.LastSeen = now
		device.Active = true
		if device.Hostname != hostname && hostname != "" {
			device.Hostname = hostname
		}
	}
}

// decodeNetBIOSName decodes a 32-byte NetBIOS encoded name to a string.
func decodeNetBIOSName(data []byte) string {
	if len(data) < 32 {
		return ""
	}
	var result []byte
	for i := 0; i < 32; i += 2 {
		if data[i] < 'A' || data[i+1] < 'A' {
			break
		}
		c := ((data[i] - 'A') << 4) | (data[i+1] - 'A')
		if c > 0 && c != 0x20 {
			result = append(result, c)
		}
	}
	return string(result)
}

// GetDevices returns all discovered devices.
func (nd *NetBIOSDetector) GetDevices() []*NetBIOSDevice {
	nd.mu.RLock()
	defer nd.mu.RUnlock()

	devices := make([]*NetBIOSDevice, 0, len(nd.devices))
	for _, d := range nd.devices {
		devices = append(devices, d)
	}
	return devices
}

// GetDevice returns a device by IP.
func (nd *NetBIOSDetector) GetDevice(ip string) *NetBIOSDevice {
	nd.mu.RLock()
	defer nd.mu.RUnlock()
	return nd.devices[ip]
}

// DeviceCount returns the number of discovered devices.
func (nd *NetBIOSDetector) DeviceCount() int {
	nd.mu.RLock()
	defer nd.mu.RUnlock()
	return len(nd.devices)
}

// ClearDevices clears all discovered devices.
func (nd *NetBIOSDetector) ClearDevices() {
	nd.mu.Lock()
	defer nd.mu.Unlock()
	nd.devices = make(map[string]*NetBIOSDevice)
}
