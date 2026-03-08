package engine

import (
	"context"
	"net"

	"github.com/bacot120211/netkit-go/pkg/session"
)

// Packet represents a raw or processed network packet
type Packet struct {
	ID          uint64
	Timestamp   int64
	Source      string
	SourcePort  uint16
	Dest        string
	DestPort    uint16
	Protocol    string
	Payload     []byte
	PID         uint32
	ProcessName string
	Metadata    map[string]interface{}
	Conn        *ConnInfo
}

// Mirror defines an interface for passive traffic cloning
type Mirror interface {
	Clone(payload []byte)
	Close() error
}

// PacketWriter defines an interface for protocol-specific packet logging (e.g. PCAP)
type PacketWriter interface {
	WritePacket(data []byte) error
	Close() error
}

// Engine is the heart of the toolkit
type Engine interface {
	Start(ctx context.Context) error
	Stop() error

	// Interceptor management
	RegisterInterceptor(i Interceptor)

	// Session management
	SessionManager() session.Manager

	// Connection management
	OnConnect(info *ConnInfo) *TunnelConfig

	// Exporters
	SetPcapWriter(w PacketWriter)
	SetFilter(f *Filter)
	AddMirror(m Mirror)

	// Ingest manually injects a packet into the engine pipeline (asynchronous)
	Ingest(p *Packet)

	// Process runs the packet through the interceptor pipeline synchronously (blocking)
	// Useful for MITM proxies that need to modify/drop data before forwarding.
	Process(p *Packet, responder func([]byte) error) Action

	// SetWorkerCount sets the number of processing workers.
	SetWorkerCount(n int)

	// GetCA returns the Root CA used by the engine
	GetCA() interface {
		GetCertPEM() []byte
	}
}

// TunnelConfig stores configuration for proxy, WireGuard, or CGNAT tunnels
type TunnelConfig struct {
	Type     string       // "proxy", "wg", "cgnat", "ssh", "drop"
	URL      string       // For proxy
	WGConfig string       // For wg
	SSH      *SSHConfig   // For ssh
	CGNAT    *CGNATConfig // For cgnat bypass
}

// SSHConfig holds SSH tunnel configuration.
type SSHConfig struct {
	Host       string
	Port       int
	User       string
	Pass       string
	PrivateKey string // Optional: Base64 or path to private key
}

// CGNATConfig holds CGNAT bypass configuration.
type CGNATConfig struct {
	RelayAddr    string // Relay server address for symmetric NAT fallback
	AuthToken    string // Authentication token for relay
	EncryptKey   []byte // 32-byte XChaCha20-Poly1305 key
	MikroTikHost string // MikroTik router IP (optional)
	MikroTikUser string // MikroTik API username (optional)
	MikroTikPass string // MikroTik API password (optional)
	AutoDetect   bool   // Auto-detect NAT type and choose strategy
}

// ConnInfo represents a connection's metadata
type ConnInfo struct {
	Type    string // "http", "socks5", "tunnelclient", "server"
	Source  string
	Dest    string
	IP      string // Client IP
	Through string // "localhost", "private", "public", or "domain"
	Path    string // Full HTTP path if available
}

// GetIPType returns "localhost", "private", or "public" based on the IP address.
func GetIPType(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "unknown"
	}
	if ip.IsLoopback() {
		return "localhost"
	}
	if ip.IsPrivate() {
		return "private"
	}
	return "public"
}

// PacketContext provides the context for an interception event
type PacketContext struct {
	Packet    *Packet
	Session   *session.Session
	Action    Action
	Responder func([]byte) error // Optional: writes data back to the packet source
	Connect   *TunnelConfig      // Optional: dynamic tunnel configuration
	AdResult  interface{}        // Optional: ad-blocking metadata (to avoid circular dependency, using interface{})
	Priority  int                // Optional: priority level for the packet/flow
	Conn      *ConnInfo          // Connection metadata
}

// Interceptor defines the interface for packet/stream manipulation
type Interceptor interface {
	Name() string
	OnConnect(info *ConnInfo) *TunnelConfig
	OnPacket(ctx *PacketContext) error
}

// Action dictates what to do with the packet
type Action int

const (
	ActionContinue Action = iota
	ActionDrop
	ActionModified
	ActionReplay
	ActionBypass
)
