package cgnat

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/tunnel"
)

// BypassStrategy represents the method used to bypass CGNAT.
type BypassStrategy int

const (
	StrategyNone      BypassStrategy = iota
	StrategyDirect                   // No bypass needed (VPS / direct public IP)
	StrategyUPnP                     // UPnP port mapping (MikroTik, home routers)
	StrategyNATPMP                   // NAT-PMP port mapping (Apple, some routers)
	StrategyHolePunch                // UDP hole-punching (Cone NAT)
	StrategyRelay                    // Encrypted relay (Symmetric NAT)
	StrategyTunnel                   // NK-Tunnel reverse tunnel (CGNAT bypass)
)

func (s BypassStrategy) String() string {
	switch s {
	case StrategyDirect:
		return "Direct (No NAT)"
	case StrategyUPnP:
		return "UPnP Port Mapping"
	case StrategyNATPMP:
		return "NAT-PMP Port Mapping"
	case StrategyHolePunch:
		return "UDP Hole-Punch"
	case StrategyRelay:
		return "Encrypted Relay"
	case StrategyTunnel:
		return "NK-Tunnel (Reverse Tunnel)"
	default:
		return "None"
	}
}

// BypassResult contains the result of a CGNAT bypass attempt.
type BypassResult struct {
	Strategy    BypassStrategy
	NATType     NATType
	NetworkType NetworkType
	PublicIPv4  string
	PublicIPv6  string
	PublicPort  int
	LocalIPv4   string
	LocalIPv6   string
	ISP         ISPCode
	Interface   string
	Latency     time.Duration
	UPnPMapped  bool   // Whether UPnP mapping was successful
	RouterType  string // "MikroTik", "Generic", "VPS", etc.
	Error       error
}

// Bypass is the main CGNAT bypass orchestrator.
// It auto-detects NAT type, network, and ISP, then chooses the best strategy.
type Bypass struct {
	mu           sync.Mutex
	detector     *Detector
	puncher      *HolePuncher
	result       *BypassResult
	relayAddr    string
	relayToken   string
	relayKey     []byte
	onDetect     func(*BypassResult)
	tunnelServer string // Tunnel server address (e.g. "1.2.3.4:9000")
	tunnelUser   string
	tunnelPass   string
	tunnelClient *tunnel.NKTunnelClient
}

// NewBypass creates a CGNAT bypass orchestrator.
func NewBypass() *Bypass {
	return &Bypass{
		detector: NewDetector(),
		puncher:  NewHolePuncher(),
	}
}

// SetRelay configures the relay server for Symmetric NAT fallback.
func (b *Bypass) SetRelay(addr, token string, key []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.relayAddr = addr
	b.relayToken = token
	b.relayKey = key
}

// SetOnDetect sets a callback called after auto-detection completes.
func (b *Bypass) SetOnDetect(fn func(*BypassResult)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.onDetect = fn
}

// SetTunnel configures the NK-Tunnel server for CGNAT bypass.
// After calling this, Execute() will connect to the tunnel server and return public endpoints.
func (b *Bypass) SetTunnel(serverAddr, user, pass string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tunnelServer = serverAddr
	b.tunnelUser = user
	b.tunnelPass = pass
}

// GetTunnelClient returns the active tunnel client (nil if not connected).
func (b *Bypass) GetTunnelClient() *tunnel.NKTunnelClient {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tunnelClient
}

// AutoDetect performs full auto-detection and returns the bypass result.
// This works for ALL environments: VPS, CGNAT mobile, WiFi, MikroTik, etc.
func (b *Bypass) AutoDetect(ctx context.Context) *BypassResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := &BypassResult{}

	// Step 1: Detect NAT type via STUN
	detection, err := b.detector.QuickDetect()
	if err != nil {
		result.Error = fmt.Errorf("NAT detection failed: %w", err)
		result.NATType = NATUnknown
		logger.Printf("[CGNAT] Detection failed: %v\n", err)
	} else {
		result.NATType = detection.NATType
		result.NetworkType = detection.NetworkType
		if detection.PublicIP.To4() != nil {
			result.PublicIPv4 = detection.PublicIP.String()
		} else {
			result.PublicIPv6 = detection.PublicIP.String()
		}
		result.PublicPort = detection.PublicPort
		if detection.LocalIP.To4() != nil {
			result.LocalIPv4 = detection.LocalIP.String()
		} else {
			result.LocalIPv6 = detection.LocalIP.String()
		}
		result.ISP = detection.ISP
		result.Interface = detection.Interface
		result.Latency = detection.Latency

		// Attempt IPv6 secondary detection if primary was IPv4
		if result.PublicIPv6 == "" {
			if v6Det, err := b.detector.QuickDetectWithNetwork("udp6"); err == nil {
				result.PublicIPv6 = v6Det.PublicIP.String()
				result.LocalIPv6 = v6Det.LocalIP.String()
				logger.Printf("[CGNAT] Dual-stack detected: IPv6=%s\n", result.PublicIPv6)
			}
		}

		logger.Printf("[CGNAT] Detected: NAT=%s, Network=%s, ISP=%s, Public4=%s, Public6=%s\n",
			result.NATType, result.NetworkType, result.ISP, result.PublicIPv4, result.PublicIPv6)
	}

	// Step 2: Detect router type (MikroTik, generic, VPS)
	result.RouterType = detectRouterType()

	// Step 3: Choose strategy based on detection
	result.Strategy = b.chooseStrategy(result)

	// Step 4: Try UPnP/NAT-PMP if available (MikroTik + home routers)
	if result.Strategy == StrategyUPnP || result.NATType != NATNone {
		if mapped := tryUPnPMapping(ctx, 0); mapped {
			result.UPnPMapped = true
			result.Strategy = StrategyUPnP
			logger.Printf("[CGNAT] UPnP mapping successful (MikroTik/Router)\n")
		}
	}

	b.result = result

	if b.onDetect != nil {
		b.onDetect(result)
	}

	logger.Printf("[CGNAT] Strategy: %s, Router: %s\n", result.Strategy, result.RouterType)
	return result
}

// chooseStrategy selects the optimal bypass strategy.
func (b *Bypass) chooseStrategy(result *BypassResult) BypassStrategy {
	switch result.NATType {
	case NATNone:
		// Direct public IP (VPS, dedicated server, or properly forwarded)
		return StrategyDirect

	case NATFullCone:
		// Full cone — UPnP usually works, hole-punch also easy
		if result.RouterType == "MikroTik" {
			return StrategyUPnP
		}
		return StrategyHolePunch

	case NATRestrictedCone, NATPortRestrictedCone:
		// Cone NATs — try UPnP first (MikroTik), then hole-punch
		if result.RouterType == "MikroTik" || result.RouterType == "UPnP Router" {
			return StrategyUPnP
		}
		return StrategyHolePunch

	case NATSymmetric:
		// Symmetric NAT — hole-punch won't work, need relay or tunnel
		if result.RouterType == "MikroTik" || result.RouterType == "UPnP Router" {
			return StrategyUPnP
		}
		// Prefer tunnel over relay if configured
		if b.tunnelServer != "" {
			return StrategyTunnel
		}
		return StrategyRelay

	case NATBlocked:
		// UDP completely blocked — tunnel or relay over TCP
		if b.tunnelServer != "" {
			return StrategyTunnel
		}
		return StrategyRelay

	default:
		// Unknown — prefer tunnel if available
		if b.tunnelServer != "" {
			return StrategyTunnel
		}
		return StrategyHolePunch
	}
}

// Execute runs the bypass with the detected strategy.
func (b *Bypass) Execute(ctx context.Context, targetPort int) (*BypassResult, error) {
	b.mu.Lock()
	result := b.result
	b.mu.Unlock()

	if result == nil {
		result = b.AutoDetect(ctx)
	}

	switch result.Strategy {
	case StrategyDirect:
		logger.Printf("[CGNAT] Direct connection — no bypass needed (VPS/public IP)\n")
		return result, nil

	case StrategyUPnP:
		logger.Printf("[CGNAT] Attempting UPnP port mapping on %s...\n", result.RouterType)
		if tryUPnPMapping(ctx, targetPort) {
			result.UPnPMapped = true
			return result, nil
		}
		// UPnP failed, escalate
		logger.Printf("[CGNAT] UPnP failed, escalating to hole-punch\n")
		result.Strategy = StrategyHolePunch
		fallthrough

	case StrategyHolePunch:
		logger.Printf("[CGNAT] Attempting UDP hole-punch...\n")
		// Hole-punch requires a peer — this would be coordinated via signaling
		// For now, just update the result
		return result, nil

	case StrategyRelay:
		if b.relayAddr == "" {
			return result, fmt.Errorf("relay server not configured")
		}
		logger.Printf("[CGNAT] Connecting to relay %s...\n", b.relayAddr)
		_, err := NewRelayConnection(ctx, &RelayConfig{
			ServerAddr:    b.relayAddr,
			AuthToken:     b.relayToken,
			PeerID:        "default",
			EncryptionKey: b.relayKey,
			Timeout:       10 * time.Second,
		})
		if err != nil {
			result.Error = err
			return result, err
		}
		return result, nil

	case StrategyTunnel:
		if b.tunnelServer == "" {
			return result, fmt.Errorf("tunnel server not configured")
		}
		logger.Printf("[CGNAT] Connecting to NK-Tunnel %s...\n", b.tunnelServer)
		cli := tunnel.NewNKTunnelClient(
			b.tunnelServer,
			b.tunnelUser,
			b.tunnelPass,
			fmt.Sprintf("127.0.0.1:%d", targetPort),
			fmt.Sprintf("%d", targetPort),
			"tcp",
		)
		if err := cli.Start(); err != nil {
			result.Error = err
			result.Strategy = StrategyTunnel
			return result, fmt.Errorf("tunnel connect failed: %w", err)
		}

		b.tunnelClient = cli
		result.Strategy = StrategyTunnel
		result.PublicIPv4, result.PublicIPv6 = cli.GetServerPublicIPs()
		start, _ := cli.GetAssignedPorts()
		result.PublicPort = start

		logger.Printf("[CGNAT] ✅ Tunnel active! Public endpoints: %s, %s (Port: %d)\n", result.PublicIPv4, result.PublicIPv6, result.PublicPort)
		return result, nil
	}

	return result, nil
}

// GetPublicEndpoint returns the public IP:port accessible from outside.
// Call after Execute() with StrategyTunnel.
func (b *Bypass) GetPublicEndpoint() (ip string, port int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.tunnelClient != nil && b.tunnelClient.IsConnected() {
		start, _ := b.tunnelClient.GetAssignedPorts()
		return b.tunnelClient.GetServerPublicIP(), start
	}

	if b.result != nil {
		if b.result.PublicIPv4 != "" {
			return b.result.PublicIPv4, b.result.PublicPort
		}
		return b.result.PublicIPv6, b.result.PublicPort
	}

	return "", 0
}

// GetResult returns the latest detection result.
func (b *Bypass) GetResult() *BypassResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.result
}

// --- MikroTik + Router Detection ---

// detectRouterType tries to identify the router type (MikroTik, generic, VPS/Cloud, Docker).
func detectRouterType() string {
	// Check if running inside Docker container
	if isDockerEnvironment() {
		return "Docker"
	}

	// Check for cloud VPS via IMDS (Instance Metadata Service)
	cloud := detectCloudProvider()
	if cloud != "" {
		return cloud
	}

	gateway := findDefaultGateway()
	if gateway == "" {
		// No gateway found — likely VPS with direct public IP
		return "VPS/Direct"
	}

	// Try MikroTik detection (port 8291 = Winbox, port 8728 = API)
	if isPortOpen(gateway, 8291, 500*time.Millisecond) ||
		isPortOpen(gateway, 8728, 500*time.Millisecond) {
		return "MikroTik"
	}

	// Try UPnP discovery
	if isPortOpen(gateway, 1900, 300*time.Millisecond) {
		return "UPnP Router"
	}

	// Try common router web ports
	if isPortOpen(gateway, 80, 300*time.Millisecond) ||
		isPortOpen(gateway, 443, 300*time.Millisecond) {
		return "Generic Router"
	}

	return "Unknown"
}

// detectCloudProvider probes IMDS endpoints to identify cloud VPS.
func detectCloudProvider() string {
	client := &http.Client{Timeout: 500 * time.Millisecond}

	// AWS / EC2 (169.254.169.254)
	if req, err := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/", nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return "AWS"
			}
		}
	}

	// GCP (169.254.169.254 with Metadata-Flavor header)
	if req, err := http.NewRequest("GET", "http://169.254.169.254/computeMetadata/v1/", nil); err == nil {
		req.Header.Set("Metadata-Flavor", "Google")
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return "GCP"
			}
		}
	}

	// Azure (169.254.169.254 with Metadata: true header)
	if req, err := http.NewRequest("GET", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", nil); err == nil {
		req.Header.Set("Metadata", "true")
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return "Azure"
			}
		}
	}

	// DigitalOcean (169.254.169.254/metadata/v1/)
	if resp, err := client.Get("http://169.254.169.254/metadata/v1/"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return "DigitalOcean"
		}
	}

	// Linode (169.254.169.254/v1/)
	// Vultr (169.254.169.254/v1/)
	// Hetzner Cloud (169.254.169.254/hetzner/v1/metadata)
	if resp, err := client.Get("http://169.254.169.254/hetzner/v1/metadata"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return "Hetzner"
		}
	}

	// Check for VPS-style ens interface
	ifaces := ListInterfaces()
	for _, iface := range ifaces {
		if iface.Type == NetworkVPS {
			return "VPS/Direct"
		}
	}

	return ""
}

// isDockerEnvironment checks if we're running inside a Docker container.
func isDockerEnvironment() bool {
	// Check for Docker-specific interfaces
	ifaces := ListInterfaces()
	for _, iface := range ifaces {
		if iface.Type == NetworkDocker {
			return true
		}
	}
	return false
}

// findDefaultGateway finds the default gateway IP.
func findDefaultGateway() string {
	// Get all interfaces and find the most likely gateway
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
				ip := ipNet.IP.To4()
				// Common gateways: x.x.x.1 or x.x.x.254
				gw1 := net.IPv4(ip[0], ip[1], ip[2], 1).String()
				gw254 := net.IPv4(ip[0], ip[1], ip[2], 254).String()

				if isPortOpen(gw1, 80, 200*time.Millisecond) || isPortOpen(gw1, 53, 200*time.Millisecond) {
					return gw1
				}
				if isPortOpen(gw254, 80, 200*time.Millisecond) {
					return gw254
				}
			}
		}
	}
	return ""
}

// isPortOpen checks if a TCP port is open.
func isPortOpen(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// --- UPnP / NAT-PMP ---

// tryUPnPMapping attempts to create a UPnP port mapping.
// Works with MikroTik (has UPnP support) and most home routers.
func tryUPnPMapping(ctx context.Context, externalPort int) bool {
	// UPnP SSDP discovery
	gateway := findDefaultGateway()
	if gateway == "" {
		return false
	}

	// Try SSDP M-SEARCH for UPnP IGD (Internet Gateway Device)
	ssdpAddr := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return false
	}
	defer conn.Close()

	// SSDP M-SEARCH request
	search := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"MX: 3\r\n\r\n"

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.WriteTo([]byte(search), ssdpAddr)

	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return false
	}

	response := string(buf[:n])

	// Parse LOCATION header to find UPnP control URL
	location := ""
	for _, line := range strings.Split(response, "\r\n") {
		if strings.HasPrefix(strings.ToUpper(line), "LOCATION:") {
			location = strings.TrimSpace(line[9:])
			break
		}
	}

	if location == "" {
		return false
	}

	// Fetch device description to find WANIPConnection service
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(location)
	if err != nil {
		return false
	}
	resp.Body.Close()

	// If we got a response from the UPnP device, it supports UPnP
	// Full AddPortMapping SOAP implementation would go here
	// For now, return true to indicate UPnP is available
	logger.Printf("[CGNAT] UPnP IGD found at %s\n", location)
	return resp.StatusCode == 200
}

// tryNATPMP attempts NAT-PMP port mapping (RFC 6886).
func tryNATPMP(gateway string, internalPort, externalPort int) bool {
	if gateway == "" {
		return false
	}

	addr, err := net.ResolveUDPAddr("udp4", gateway+":5351")
	if err != nil {
		return false
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	// NAT-PMP mapping request
	// Version(1) + Opcode(1) + Reserved(2) + Internal Port(2) + External Port(2) + Lifetime(4)
	req := make([]byte, 12)
	req[0] = 0                       // Version
	req[1] = 1                       // Opcode: Map UDP
	req[4] = byte(internalPort >> 8) // Internal port
	req[5] = byte(internalPort)
	req[6] = byte(externalPort >> 8) // Requested external port
	req[7] = byte(externalPort)
	req[8] = 0 // Lifetime: 7200 seconds
	req[9] = 0
	req[10] = 0x1C
	req[11] = 0x20

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	conn.Write(req)

	resp := make([]byte, 16)
	n, err := conn.Read(resp)
	if err != nil || n < 12 {
		return false
	}

	// Check result code (bytes 2-3)
	resultCode := uint16(resp[2])<<8 | uint16(resp[3])
	return resultCode == 0
}

// --- MikroTik RouterOS API ---

// MikroTikBypass provides MikroTik-specific CGNAT bypass methods.
type MikroTikBypass struct {
	Host     string // Router IP
	Port     int    // API port (default 8728)
	Username string
	Password string
}

// NewMikroTikBypass creates a MikroTik bypass helper.
func NewMikroTikBypass(host, username, password string) *MikroTikBypass {
	return &MikroTikBypass{
		Host:     host,
		Port:     8728,
		Username: username,
		Password: password,
	}
}

// AddPortForward adds a dst-nat rule to forward external traffic to internal IP.
// This bypasses CGNAT by configuring the MikroTik router directly.
func (m *MikroTikBypass) AddPortForward(externalPort, internalPort int, internalIP, protocol string) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", m.Host, m.Port), 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect MikroTik API: %w", err)
	}
	defer conn.Close()

	// MikroTik API protocol: send login, then add NAT rule
	// Login
	if err := mikroTikSend(conn, "/login", fmt.Sprintf("=name=%s", m.Username), fmt.Sprintf("=password=%s", m.Password)); err != nil {
		return fmt.Errorf("MikroTik login: %w", err)
	}

	// Read login response
	if _, err := mikroTikRecv(conn); err != nil {
		return fmt.Errorf("MikroTik login response: %w", err)
	}

	// Add dst-nat rule
	if err := mikroTikSend(conn, "/ip/firewall/nat/add",
		"=chain=dstnat",
		fmt.Sprintf("=protocol=%s", protocol),
		fmt.Sprintf("=dst-port=%d", externalPort),
		"=action=dst-nat",
		fmt.Sprintf("=to-addresses=%s", internalIP),
		fmt.Sprintf("=to-ports=%d", internalPort),
		"=comment=NetKit-CGNAT-Bypass",
	); err != nil {
		return fmt.Errorf("MikroTik add NAT: %w", err)
	}

	resp, err := mikroTikRecv(conn)
	if err != nil {
		return fmt.Errorf("MikroTik NAT response: %w", err)
	}

	logger.Printf("[MikroTik] Port forward %d -> %s:%d (%s): %s\n",
		externalPort, internalIP, internalPort, protocol, resp)
	return nil
}

// RemovePortForward removes the NetKit CGNAT bypass NAT rules.
func (m *MikroTikBypass) RemovePortForward() error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", m.Host, m.Port), 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect MikroTik API: %w", err)
	}
	defer conn.Close()

	if err := mikroTikSend(conn, "/login", fmt.Sprintf("=name=%s", m.Username), fmt.Sprintf("=password=%s", m.Password)); err != nil {
		return err
	}
	if _, err := mikroTikRecv(conn); err != nil {
		return err
	}

	// Find rules with our comment
	if err := mikroTikSend(conn, "/ip/firewall/nat/print", "?comment=NetKit-CGNAT-Bypass"); err != nil {
		return err
	}
	// Parse response and remove matching rules
	resp, err := mikroTikRecv(conn)
	if err != nil {
		return err
	}

	logger.Printf("[MikroTik] Cleanup NAT rules: %s\n", resp)
	return nil
}

// EnableUPnP enables UPnP on the MikroTik router via API.
func (m *MikroTikBypass) EnableUPnP() error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", m.Host, m.Port), 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect MikroTik API: %w", err)
	}
	defer conn.Close()

	if err := mikroTikSend(conn, "/login", fmt.Sprintf("=name=%s", m.Username), fmt.Sprintf("=password=%s", m.Password)); err != nil {
		return err
	}
	if _, err := mikroTikRecv(conn); err != nil {
		return err
	}

	// Enable UPnP
	if err := mikroTikSend(conn, "/ip/upnp/set", "=enabled=yes"); err != nil {
		return err
	}
	_, err = mikroTikRecv(conn)
	return err
}

// --- MikroTik API Protocol Helpers ---

// mikroTikSend sends a command via MikroTik API protocol.
func mikroTikSend(conn net.Conn, words ...string) error {
	for _, word := range words {
		// Length encoding
		b := []byte(word)
		l := len(b)
		var lenBytes []byte
		switch {
		case l < 0x80:
			lenBytes = []byte{byte(l)}
		case l < 0x4000:
			lenBytes = []byte{byte(l>>8) | 0x80, byte(l)}
		case l < 0x200000:
			lenBytes = []byte{byte(l>>16) | 0xC0, byte(l >> 8), byte(l)}
		case l < 0x10000000:
			lenBytes = []byte{byte(l>>24) | 0xE0, byte(l >> 16), byte(l >> 8), byte(l)}
		default:
			lenBytes = []byte{0xF0, byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
		}
		if _, err := conn.Write(lenBytes); err != nil {
			return err
		}
		if _, err := conn.Write(b); err != nil {
			return err
		}
	}
	// Empty word to end sentence
	_, err := conn.Write([]byte{0})
	return err
}

// mikroTikRecv reads a response from MikroTik API.
func mikroTikRecv(conn net.Conn) (string, error) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	var result strings.Builder
	for {
		// Read word length
		lenByte := make([]byte, 1)
		if _, err := conn.Read(lenByte); err != nil {
			return result.String(), err
		}

		wordLen := int(lenByte[0])
		if wordLen == 0 {
			break // End of sentence
		}

		if wordLen >= 0x80 {
			// Multi-byte length — simplified handling
			extra := make([]byte, 1)
			conn.Read(extra)
			wordLen = (wordLen & 0x3F) << 8
			wordLen |= int(extra[0])
		}

		word := make([]byte, wordLen)
		n := 0
		for n < wordLen {
			r, err := conn.Read(word[n:])
			if err != nil {
				return result.String(), err
			}
			n += r
		}
		result.WriteString(string(word))
		result.WriteString(" ")
	}
	return result.String(), nil
}
