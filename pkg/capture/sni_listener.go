package capture

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/protocol/tls"
	"github.com/bacot120211/netkit-go/pkg/proxy"
	utls "github.com/refraction-networking/utls"
)

// SNIListener listens for TLS connections and peeks at the SNI before MITM.
// This is used for transparent redirection (hosts file) where the target host
// is unknown at the listener level.
type SNIListener struct {
	addr          string
	engine        engine.Engine
	TLSInt        *tls.TLSInterceptor
	Sniffer       *Sniffer
	ResolvedIPs   map[string]string
	CustomTLSSpec *utls.ClientHelloSpec
	// CapturesDir: if non-empty, raw passthrough bytes are written here as
	// captures/<hostname>/<ts>_passthrough_{c2s,s2c}.bin
	CapturesDir string
	ForceHTTP11 bool
	// TLSSessionTicketKey: hex string of 32 bytes
	TLSSessionTicketKey string
	// StrictInterceptDomains: if hostname matches, NEVER fallback to passthrough
	StrictInterceptDomains []string
	ShouldMITM             func(hostname string) bool
	Verbose                bool
	mu                     sync.RWMutex
}

func NewSNIListener(addr string, ca *tls.CA, e engine.Engine, resolvedIPs map[string]string) *SNIListener {
	tlsInt := tls.NewTLSInterceptor(ca, e)
	tlsInt.ResolvedIPs = resolvedIPs
	tlsInt.Verbose = false // Default to false, manager will set it if needed
	return &SNIListener{
		addr:        addr,
		engine:      e,
		TLSInt:      tlsInt,
		ResolvedIPs: resolvedIPs,
	}
}

func (l *SNIListener) Start(ctx context.Context) error {
	l.TLSInt.ForceHTTP11 = l.ForceHTTP11 // Pass the flag to interceptor before starting

	if l.TLSSessionTicketKey != "" {
		key, err := hex.DecodeString(l.TLSSessionTicketKey)
		if err == nil && len(key) == 32 {
			var ticketKey [32]byte
			copy(ticketKey[:], key)
			l.TLSInt.SessionTicketKey = ticketKey
			l.TLSInt.UseSessionTicket = true
			logger.Printf("[SNI] 🎫 Session tickets enabled using provided key\n")
		} else {
			logger.Printf("[SNI] ⚠️  Invalid session ticket key (must be 32 bytes hex): %v\n", err)
		}
	}

	listener, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("[SNI] failed to listen on %s: %w", l.addr, err)
	}
	defer listener.Close()

	fmt.Printf("[SNI] 🛡️ SNI-Aware Listener active on %s\n", l.addr)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}
		go l.handleConn(conn)
	}
}

func (l *SNIListener) handleConn(conn net.Conn) {
	// NOTE: We do NOT defer conn.Close() here because:
	// - On MITM success: HandleMITM manages the connection lifecycle
	// - On early error: we close explicitly

	// Set a generous deadline to read the TLS ClientHello header (wait for slow clients)
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	// Robust Peeking: Read enough bytes for TLS record header (5 bytes)
	header := make([]byte, 5)
	_, err := io.ReadFull(conn, header)
	if err != nil {
		if err != io.EOF {
			logger.Printf("[SNI] ❌ Failed to read TLS header from %s: %v\n", conn.RemoteAddr(), err)
		}
		conn.Close()
		return
	}

	// Reset deadline
	_ = conn.SetReadDeadline(time.Time{})

	if header[0] != 22 { // Not a TLS Handshake
		conn.Close()
		return
	}

	// Get record length
	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen > 16384 { // Sanity check
		conn.Close()
		return
	}

	// Read the record body
	body := make([]byte, recordLen)
	_, err = io.ReadFull(conn, body)
	if err != nil {
		logger.Printf("[SNI] ❌ Failed to read TLS body (%d bytes) from %s: %v\n", recordLen, conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	fullPayload := append(header, body...)

	hostname := ""
	alpn := ""
	var protos []string

	ch, err := tls.ParseClientHello(fullPayload)
	if err == nil {
		if ch.SNI != "" {
			hostname = ch.SNI
		}
		if len(ch.ALPN) > 0 {
			protos = ch.ALPN
			alpn = fmt.Sprintf(" (ALPN: %v)", ch.ALPN)
		}
	}

	if hostname == "" {
		// No SNI detected — cannot determine target host.
		// Drop connection instead of guessing (prevents misrouted traffic).
		logger.Printf("[SNI] ⚠️  No SNI detected from %s. Dropping connection (cannot MITM without target host).%s\n", conn.RemoteAddr(), alpn)
		conn.Close()
		return
	} else if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" || hostname == "[::1]" {
		logger.Printf("[SNI] 🛡️  Local connection (%s) from %s. MITM active.%s\n", hostname, conn.RemoteAddr(), alpn)
	}

	// Learn mapping for Sniffer
	if l.Sniffer != nil {
		remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		l.Sniffer.AddDomainMapping(remoteIP, hostname)
	}

	if l.Verbose {
		logger.Printf("[SNI] 🔌 Intercepted connection for %s%s\n", hostname, alpn)
		// Log JA3 hash for all clients (informational only)
		ja3Str, ja3Hash := tls.CalculateJA3(fullPayload)
		logger.Printf("[SNI] ℹ️  Client JA3: %s (Raw: %s)\n", ja3Hash, ja3Str)
	}

	// Create a connection that "replays" the peeked data
	peekedConn := &tls.PeekedConn{
		Conn: conn,
		Data: fullPayload,
	}

	// ALL connections MUST go through MITM — no passthrough fallback.
	// Retry up to 3 times with 2s delay to handle transient network issues.
	const maxRetries = 3
	const retryDelay = 2 * time.Second

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			logger.Printf("[SNI] 🔄 Retry %d/%d for %s...\n", attempt, maxRetries, hostname)
			time.Sleep(retryDelay)
			// Re-create peekedConn to reset the replay offset
			peekedConn = &tls.PeekedConn{
				Conn: conn,
				Data: fullPayload,
			}
		}

		localAddr := conn.LocalAddr().String()
		localHost, _, _ := net.SplitHostPort(localAddr)

		connInfo := &engine.ConnInfo{
			Type:    "sni",
			Source:  peekedConn.RemoteAddr().String(),
			Dest:    hostname,
			IP:      peekedConn.RemoteAddr().String(),
			Through: engine.GetIPType(localHost),
		}

		// Check if JS returned a 'drop' signal via OnConnect
		if cfg := l.engine.OnConnect(connInfo); cfg != nil && strings.ToLower(cfg.Type) == "drop" {
			logger.Printf("[SNI] 🚫 Connection dropped by OnConnect for %s\n", conn.RemoteAddr())
			conn.Close()
			return
		}

		// Check if MITM is required for this hostname
		if l.ShouldMITM != nil && !l.ShouldMITM(hostname) {
			if l.IsStrictDomain(hostname) {
				// Continue to MITM anyway
			} else {
				logger.Printf("[SNI] ⏩ Skipping MITM for %s (not in sniff list). Falling back to passthrough.\n", hostname)
				l.handlePassthrough(conn, fullPayload, hostname, utls.HelloGolang, nil, connInfo)
				return
			}
		}

		lastErr = l.TLSInt.HandleMITM(peekedConn, "", hostname, protos, nil, connInfo)
		if lastErr == nil {
			return // Success
		}

		logger.Printf("[SNI] ❌ MITM attempt %d/%d failed for %s: %v\n", attempt, maxRetries, hostname, lastErr)
	}

	// All retries exhausted
	logger.Printf("[SNI] 🚫 MITM FAILED after %d attempts for %s: %v. Connection dropped (passthrough disabled).\n", maxRetries, hostname, lastErr)
	conn.Close()
}

func (l *SNIListener) AddStrictDomain(domain string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, d := range l.StrictInterceptDomains {
		if d == domain {
			return
		}
	}
	l.StrictInterceptDomains = append(l.StrictInterceptDomains, domain)
}

func (l *SNIListener) IsStrictDomain(domain string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, d := range l.StrictInterceptDomains {
		if d == domain {
			return true
		}
	}
	return false
}

// handlePassthrough creates a direct TCP tunnel to the real server,
// intercepting and modifying the ClientHello using uTLS if specified,
// or replaying the original ClientHello directly if not.
// This allows clients that don't trust our CA to still reach the server, while we spoof their fingerprint.
// If CapturesDir is set, raw bytes (TLS ciphertext) are also written to files for debugging.
func (l *SNIListener) handlePassthrough(clientConn net.Conn, clientHello []byte, hostname string, utlsID utls.ClientHelloID, utlsSpec *utls.ClientHelloSpec, connInfo *engine.ConnInfo) {
	defer clientConn.Close()

	// Resolve real server IP
	var dialAddr string
	if realIP, ok := l.ResolvedIPs[hostname]; ok {
		dialAddr = net.JoinHostPort(realIP, "443")
	} else {
		dialAddr = net.JoinHostPort(hostname, "443")
	}

	// Connect to real server (raw TCP)
	rawServerConn, err := net.DialTimeout("tcp", dialAddr, 5*time.Second)
	if err != nil {
		logger.Printf("[SNI] ❌ Passthrough dial failed for %s (%s): %v\n", hostname, dialAddr, err)
		return
	}
	defer rawServerConn.Close()

	var serverConn net.Conn = rawServerConn

	// If a uTLS profile was provided, perform the TLS handshake using uTLS
	// Note: since this is transparent passthrough of TCP bytes, if we use uTLS here
	// we will decrypt traffic on our end for the server connection, but the original client
	// still expects its original ClientHello to be raw-forwarded. So we cannot easily "MITM"
	// just the ClientHello without also doing full TLS MITM (which we are explicitly trying to avoid for strict clients).
	// Because of this, for pure TCP passthrough, we MUST replay the original client hello.

	logger.Printf("[SNI] ✅ Passthrough active: %s <-> %s (%s)\n", clientConn.RemoteAddr(), dialAddr, hostname)

	// Use Relay to ensure all TCP traffic (including responses) flows through the engine hooks
	relay := proxy.NewRelay(l.engine, hostname, false)
	relay.Start(clientConn, serverConn)
}
