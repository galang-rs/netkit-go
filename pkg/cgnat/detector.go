package cgnat

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// NATType represents the detected NAT behavior.
type NATType int

const (
	NATUnknown            NATType = iota
	NATNone                       // Direct public IP (no NAT)
	NATFullCone                   // Full Cone NAT (least restrictive)
	NATRestrictedCone             // Restricted Cone NAT
	NATPortRestrictedCone         // Port-Restricted Cone NAT
	NATSymmetric                  // Symmetric NAT (most restrictive, can't hole-punch)
	NATBlocked                    // UDP blocked entirely
)

// String returns human-readable NAT type name.
func (n NATType) String() string {
	switch n {
	case NATNone:
		return "No NAT (Direct)"
	case NATFullCone:
		return "Full Cone NAT"
	case NATRestrictedCone:
		return "Restricted Cone NAT"
	case NATPortRestrictedCone:
		return "Port-Restricted Cone NAT"
	case NATSymmetric:
		return "Symmetric NAT"
	case NATBlocked:
		return "UDP Blocked"
	default:
		return "Unknown"
	}
}

// CanHolePunch returns whether this NAT type supports UDP hole-punching.
func (n NATType) CanHolePunch() bool {
	switch n {
	case NATNone, NATFullCone, NATRestrictedCone, NATPortRestrictedCone:
		return true
	default:
		return false
	}
}

// NetworkType represents the type of network interface.
type NetworkType int

const (
	NetworkUnknown  NetworkType = iota
	NetworkMobile               // 4G/5G cellular
	NetworkWiFi                 // WiFi
	NetworkEthernet             // Wired ethernet (eth0, enp, eno)
	NetworkVPS                  // VPS/Cloud (ens, AWS ENI, Azure, GCP)
	NetworkDocker               // Docker (docker0, veth, br-)
)

func (n NetworkType) String() string {
	switch n {
	case NetworkMobile:
		return "Mobile"
	case NetworkWiFi:
		return "WiFi"
	case NetworkEthernet:
		return "Ethernet"
	case NetworkVPS:
		return "VPS"
	case NetworkDocker:
		return "Docker"
	default:
		return "Unknown"
	}
}

// KeepAliveInterval returns the recommended NAT keepalive interval for this network type.
func (n NetworkType) KeepAliveInterval() time.Duration {
	switch n {
	case NetworkMobile:
		return 15 * time.Second // Mobile NATs have shortest timeout
	case NetworkWiFi:
		return 25 * time.Second
	case NetworkEthernet:
		return 30 * time.Second
	case NetworkVPS:
		return 45 * time.Second // VPS rarely drops NAT mappings
	case NetworkDocker:
		return 30 * time.Second
	default:
		return 20 * time.Second
	}
}

// DetectionResult contains the full NAT detection result.
type DetectionResult struct {
	NATType     NATType
	NetworkType NetworkType
	PublicIP    net.IP
	PublicPort  int
	LocalIP     net.IP
	LocalPort   int
	ISP         ISPCode
	STUNServer  string
	Latency     time.Duration
	Interface   string // Network interface name
}

// Detector detects NAT type and network characteristics.
type Detector struct {
	stun        *STUNClient
	stunServers []string
}

// NewDetector creates a NAT detector with default STUN servers.
func NewDetector() *Detector {
	return &Detector{
		stun:        NewSTUNClient(),
		stunServers: DefaultSTUNServers,
	}
}

// NewDetectorWithServers creates a NAT detector with custom STUN servers.
func NewDetectorWithServers(servers []string) *Detector {
	return &Detector{
		stun:        NewSTUNClient(),
		stunServers: servers,
	}
}

// Detect performs full NAT type detection using the RFC 3489 algorithm.
// This requires a STUN server that supports CHANGE-REQUEST (not all do).
func (d *Detector) Detect() (*DetectionResult, error) {
	return d.DetectWithNetwork("udp4")
}

// DetectWithNetwork performs NAT detection using a specific network ("udp4" or "udp6").
func (d *Detector) DetectWithNetwork(network string) (*DetectionResult, error) {
	result := &DetectionResult{}

	// Create a UDP socket
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: nil, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	result.LocalIP = localAddr.IP
	result.LocalPort = localAddr.Port

	// Detect network type and interface
	result.NetworkType, result.Interface = detectNetworkType()

	// Try each STUN server until one works
	var stunResult1 *STUNResult
	var workingServer string

	for _, server := range d.stunServers {
		stunResult1, err = d.stun.Bind(server, conn)
		if err == nil {
			workingServer = server
			result.STUNServer = server
			result.Latency = stunResult1.ResponseTime
			break
		}
	}

	if stunResult1 == nil {
		result.NATType = NATBlocked
		return result, nil
	}

	result.PublicIP = stunResult1.MappedAddr.IP
	result.PublicPort = stunResult1.MappedAddr.Port

	// Detect ISP from public IP
	result.ISP = detectISP(result.PublicIP)

	// Check if we have a direct connection (no NAT)
	if localAddr.IP.Equal(stunResult1.MappedAddr.IP) && localAddr.Port == stunResult1.MappedAddr.Port {
		result.NATType = NATNone
		return result, nil
	}

	// Test 2: Send binding request to second STUN server to check if mapping changes
	var stunResult2 *STUNResult
	for _, server := range d.stunServers {
		if server == workingServer {
			continue // Skip the server we already used
		}
		stunResult2, err = d.stun.Bind(server, conn)
		if err == nil {
			break
		}
	}

	if stunResult2 != nil && !stunResult1.MappedAddr.IP.Equal(stunResult2.MappedAddr.IP) {
		// Different mapped IP from different server = Symmetric NAT
		result.NATType = NATSymmetric
		return result, nil
	}

	if stunResult2 != nil && stunResult1.MappedAddr.Port != stunResult2.MappedAddr.Port {
		// Same IP but different port = Symmetric NAT (port-dependent mapping)
		result.NATType = NATSymmetric
		return result, nil
	}

	// Test 3: Try to receive from changed IP+port (CHANGE-REQUEST)
	_, err = d.stun.BindChangeIP(workingServer, conn)
	if err == nil {
		// Received response from different IP/port = Full Cone
		result.NATType = NATFullCone
		return result, nil
	}

	// Test 4: Try to receive from changed port only
	_, err = d.stun.BindChangePort(workingServer, conn)
	if err == nil {
		// Received from different port = Restricted Cone
		result.NATType = NATRestrictedCone
		return result, nil
	}

	// Failed both change tests = Port Restricted Cone
	result.NATType = NATPortRestrictedCone
	return result, nil
}

// QuickDetect does a fast NAT detection (2-server test only, no CHANGE-REQUEST).
// This works with all STUN servers including Google's.
func (d *Detector) QuickDetect() (*DetectionResult, error) {
	return d.QuickDetectWithNetwork("udp4")
}

// QuickDetectWithNetwork performs fast NAT detection using a specific network.
func (d *Detector) QuickDetectWithNetwork(network string) (*DetectionResult, error) {
	result := &DetectionResult{}

	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: nil, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	result.LocalIP = localAddr.IP
	result.LocalPort = localAddr.Port
	result.NetworkType, result.Interface = detectNetworkType()

	// Test with first server
	var r1 *STUNResult
	for _, server := range d.stunServers {
		r1, err = d.stun.Bind(server, conn)
		if err == nil {
			result.STUNServer = server
			result.Latency = r1.ResponseTime
			break
		}
	}
	if r1 == nil {
		result.NATType = NATBlocked
		return result, nil
	}

	result.PublicIP = r1.MappedAddr.IP
	result.PublicPort = r1.MappedAddr.Port
	result.ISP = detectISP(result.PublicIP)

	// No NAT check
	if localAddr.IP.Equal(r1.MappedAddr.IP) {
		result.NATType = NATNone
		return result, nil
	}

	// Test with second server (different from first)
	var r2 *STUNResult
	for _, server := range d.stunServers {
		if server == result.STUNServer {
			continue
		}
		r2, err = d.stun.Bind(server, conn)
		if err == nil {
			break
		}
	}

	if r2 == nil {
		// Only one server worked — assume restricted cone (common)
		result.NATType = NATPortRestrictedCone
		return result, nil
	}

	// Compare mappings
	if !r1.MappedAddr.IP.Equal(r2.MappedAddr.IP) || r1.MappedAddr.Port != r2.MappedAddr.Port {
		result.NATType = NATSymmetric
	} else {
		// Same mapping = Cone NAT (assume port-restricted as safe default)
		result.NATType = NATPortRestrictedCone
	}

	return result, nil
}

// detectNetworkType determines the network type from active interfaces.
func detectNetworkType() (NetworkType, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return NetworkUnknown, ""
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}

		name := strings.ToLower(iface.Name)

		// Skip Docker/bridge/veth interfaces for primary detection
		// (they are internal, not the real uplink)
		if strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") ||
			strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "cni") ||
			strings.HasPrefix(name, "flannel") || strings.HasPrefix(name, "cali") ||
			strings.HasPrefix(name, "weave") || strings.HasPrefix(name, "vxlan") {
			continue // Skip container/overlay interfaces
		}

		// Check for mobile/cellular interfaces
		if strings.Contains(name, "rmnet") || strings.Contains(name, "pdp") ||
			strings.Contains(name, "ccmni") || strings.Contains(name, "wwan") ||
			strings.Contains(name, "mobile") || strings.Contains(name, "cellular") ||
			strings.Contains(name, "lte") || strings.Contains(name, "5g") {
			return NetworkMobile, iface.Name
		}

		// Check for WiFi interfaces
		if strings.Contains(name, "wlan") || strings.Contains(name, "wifi") ||
			strings.Contains(name, "wi-fi") || strings.Contains(name, "wlp") ||
			strings.Contains(name, "ath") || strings.Contains(name, "wireless") {
			return NetworkWiFi, iface.Name
		}

		// Check for VPS/Cloud interfaces (ens = AWS/GCP/Azure/VMware)
		// ens3, ens5, ens33, ens160, ens192 — common on cloud VPS
		if strings.HasPrefix(name, "ens") {
			return NetworkVPS, iface.Name
		}

		// Check for Ethernet interfaces
		if strings.Contains(name, "eth") || strings.Contains(name, "enp") ||
			strings.Contains(name, "eno") || strings.Contains(name, "en0") ||
			strings.Contains(name, "local area") || strings.Contains(name, "ethernet") {
			return NetworkEthernet, iface.Name
		}
	}

	return NetworkUnknown, ""
}

// IsDockerInterface checks if the given interface is a Docker/container interface.
func IsDockerInterface(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "docker") || strings.HasPrefix(n, "veth") ||
		strings.HasPrefix(n, "br-") || strings.HasPrefix(n, "cni") ||
		strings.HasPrefix(n, "flannel") || strings.HasPrefix(n, "cali") ||
		strings.HasPrefix(n, "weave") || strings.HasPrefix(n, "vxlan")
}

// ISPCode represents detected ISP as a numeric code.
type ISPCode int

const (
	ISPUnknown ISPCode = iota
	ISPCGNAT           // RFC 6598 CGNAT range (100.64.0.0/10)
	ISPPrivate         // Private network (10.x, 172.16-31.x, 192.168.x)
	ISP1               // Mobile carrier 1
	ISP2               // Mobile carrier 2
	ISP3               // Mobile carrier 3
	ISP4               // Mobile carrier 4
	ISP5               // Mobile carrier 5
	ISP6               // Fiber/broadband provider 1
	ISP7               // Fiber/broadband provider 2
	ISP8               // Fiber/broadband provider 3
	ISP9               // Cable/fiber provider 4
	ISP10              // Generic/backbone provider
)

func (c ISPCode) String() string {
	switch c {
	case ISPUnknown:
		return "Unknown"
	case ISPCGNAT:
		return "CGNAT"
	case ISPPrivate:
		return "Private"
	default:
		return fmt.Sprintf("ISP-%d", int(c))
	}
}

// detectISP identifies the ISP from the public IP using known CGNAT ranges.
func detectISP(ip net.IP) ISPCode {
	if ip == nil {
		return ISPUnknown
	}

	// Check IPv6 patterns first
	if ip.To4() == nil {
		// Example: Check for NAT64 (64:ff9b::/96)
		nat64Prefix := &net.IPNet{IP: net.ParseIP("64:ff9b::"), Mask: net.CIDRMask(96, 128)}
		if nat64Prefix.Contains(ip) {
			return ISPCGNAT
		}
		// In IPv6, almost everything is direct public, but some carriers use
		// private ranges for management.
		return ISPUnknown
	}

	ip4 := ip.To4()

	// Check RFC 6598 CGNAT range (100.64.0.0/10)
	if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return ISPCGNAT
	}

	first := ip4[0]
	second := ip4[1]

	switch {
	case first == 10:
		return ISPPrivate
	case first == 172 && second >= 16 && second <= 31:
		return ISPPrivate
	case first == 192 && second == 168:
		return ISPPrivate

	// Mobile carriers (by IP range patterns)
	case first == 36 && second >= 64 && second <= 95:
		return ISP1
	case first == 114 && second >= 120 && second <= 127:
		return ISP1
	case first == 114 && second <= 7:
		return ISP2
	case first == 112 && second == 215:
		return ISP3

	// Broadband/Fiber ISPs
	case first == 180 && second >= 240:
		return ISP6
	case first == 110:
		return ISP10
	case first == 125 && second >= 160 && second <= 167:
		return ISP10
	case first == 118 && second >= 136 && second <= 143:
		return ISP8
	case first == 103 && second >= 30 && second <= 31:
		return ISP7
	case first == 124 && second == 195:
		return ISP9
	}

	return ISPUnknown
}

// ListInterfaces returns all active network interfaces with their type.
func ListInterfaces() []InterfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var result []InterfaceInfo
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}

		info := InterfaceInfo{
			Name:  iface.Name,
			MTU:   iface.MTU,
			Flags: iface.Flags.String(),
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.To4() != nil {
					info.IPv4 = ipNet.IP.String()
				} else {
					info.IPv6 = ipNet.IP.String()
				}
			}
		}

		name := strings.ToLower(iface.Name)
		switch {
		case strings.Contains(name, "rmnet") || strings.Contains(name, "wwan") || strings.Contains(name, "pdp"):
			info.Type = NetworkMobile
		case strings.Contains(name, "wlan") || strings.Contains(name, "wifi") || strings.Contains(name, "wlp"):
			info.Type = NetworkWiFi
		case strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "cni"):
			info.Type = NetworkDocker
		case strings.HasPrefix(name, "ens"):
			info.Type = NetworkVPS
		case strings.Contains(name, "eth") || strings.Contains(name, "enp") || strings.Contains(name, "eno"):
			info.Type = NetworkEthernet
		default:
			info.Type = NetworkUnknown
		}

		result = append(result, info)
	}
	return result
}

// InterfaceInfo represents a network interface with its properties.
type InterfaceInfo struct {
	Name  string
	IPv4  string
	IPv6  string
	Type  NetworkType
	MTU   int
	Flags string
}
