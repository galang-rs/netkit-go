package tls

import (
	"context"
	ctls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"io"

	"github.com/bacot120211/netkit-go/pkg/adblock"
	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/proxy"

	"http-interperation/pkg/network"

	utls "github.com/bogdanfinn/utls"
)

type TLSInterceptor struct {
	ca               *CA
	engine           engine.Engine
	ResolvedIPs      map[string]string // Hostname -> Real IP to bypass hosts file redirection
	certTemplate     map[string]*x509.Certificate
	templateMu       sync.RWMutex
	ForceHTTP11      bool
	SessionTicketKey [32]byte
	UseSessionTicket bool
	sessionCache     utls.ClientSessionCache
	nativeCache      ctls.ClientSessionCache
	Verbose          bool
}

func NewTLSInterceptor(ca *CA, e engine.Engine) *TLSInterceptor {
	return &TLSInterceptor{
		ca:           ca,
		engine:       e,
		certTemplate: make(map[string]*x509.Certificate),
		sessionCache: utls.NewLRUClientSessionCache(1024),
		nativeCache:  ctls.NewLRUClientSessionCache(1024),
		ForceHTTP11:  true, // Default to true for better compatibility with strict clients like Firefox
	}
}

func (t *TLSInterceptor) SetCRLURL(url string) {
	t.ca.SetCRLURL(url)
}

func (t *TLSInterceptor) GetCRL() ([]byte, error) {
	return t.ca.CreateCRL()
}

// Intercept attempts to perform MITM on a given connection
func (t *TLSInterceptor) Intercept(conn net.Conn, hostname string, protos []string) (net.Conn, error) {
	// 1. Generate certificate for the hostname
	t.templateMu.RLock()
	template := t.certTemplate[hostname]
	t.templateMu.RUnlock()

	var certs []ctls.Certificate
	var err error
	if template != nil {
		certs, err = t.ca.GenerateMirroredCert(hostname, template)
	} else {
		certs, err = t.ca.GenerateCert(hostname)
	}

	if err != nil {
		logger.Printf("[TLS] ❌ Failed to generate cert for %s: %v\n", hostname, err)
		return nil, logger.Errorf("failed to generate cert: %v", err)
	}

	// ALPN Strategy:
	// For Google APIs, strictly follow protocol to avoid EOF.
	// For other hosts, follow client's requested protos or fallback to h2/http/1.1.
	isGoogle := t.isGoogle(hostname)

	var targetProtos []string
	if isGoogle {
		// Strict Google domains: prefer h2 if client requested it, otherwise fallback to http/1.1
		hasClientH2 := false
		for _, p := range protos {
			if p == "h2" {
				hasClientH2 = true
				break
			}
		}
		if hasClientH2 && !t.ForceHTTP11 {
			targetProtos = []string{"h2", "http/1.1"}
		} else if len(protos) > 0 {
			// keep existing protos but ensure http/1.1 is present
			hasH1 := false
			for _, p := range protos {
				if p == "http/1.1" {
					hasH1 = true
					break
				}
			}
			if !hasH1 {
				targetProtos = append(protos, "http/1.1")
			} else {
				targetProtos = protos
			}
		} else {
			targetProtos = nil
		}
	} else if len(protos) == 0 {
		targetProtos = nil
	} else {
		// For others, we keep client's protos but ensure they are sane and unique
		uniqueProtos := make(map[string]struct{})
		var filteredProtos []string
		for _, p := range protos {
			if _, ok := uniqueProtos[p]; !ok {
				uniqueProtos[p] = struct{}{}
				filteredProtos = append(filteredProtos, p)
			}
		}
		targetProtos = filteredProtos

		if !t.ForceHTTP11 {
			// Ensure h2 is in the list if not forced to H1.1
			hasH2 := false
			for _, p := range targetProtos {
				if p == "h2" {
					hasH2 = true
					break
				}
			}
			if !hasH2 {
				// Proactively add h2 for better gRPC/SSE support
				targetProtos = append([]string{"h2"}, targetProtos...)
			}
		}

		// Ensure http/1.1 is always present
		hasH1 := false
		for _, p := range targetProtos {
			if p == "http/1.1" {
				hasH1 = true
				break
			}
		}
		if !hasH1 {
			targetProtos = append(targetProtos, "http/1.1")
		}
	}

	if t.ForceHTTP11 {
		targetProtos = []string{"http/1.1"}
	}

	// Logging ALPN intent
	if t.Verbose {
		logger.Printf("[TLS] 🛡️  ALPN Intent for %s: %v\n", hostname, targetProtos)
	}

	// 3. Wrap the connection with TLS
	config := &ctls.Config{
		Certificates: certs, // Use the generated certificates directly
		GetConfigForClient: func(hello *ctls.ClientHelloInfo) (*ctls.Config, error) {
			// Extract client details for logging
			if t.Verbose {
				logger.Printf("[TLS] 👋 Client Hello for %s: Ciphers: %v, ServerName: %s, ALPN: %v, Sigs: %v\n",
					hostname, hello.CipherSuites, hello.ServerName, hello.SupportedProtos, hello.SignatureSchemes)
			}

			// Strategy: Dynamic ALPN selection based on the passed 'protos' and client hello
			var targetProtos []string

			// Re-use isGoogle for dynamic selection
			isGoogleDomain := t.isGoogle(hostname)

			if len(hello.SupportedProtos) > 0 {
				hasH2 := false
				for _, p := range hello.SupportedProtos {
					if p == "h2" {
						hasH2 = true
						break
					}
				}

				if t.ForceHTTP11 {
					// FORCE HTTP/1.1 if requested (for easier SSE decryption)
					targetProtos = []string{"http/1.1"}
					if t.Verbose {
						logger.Printf("[TLS] ⚡ FORCING ALPN: http/1.1 for %s\n", hostname)
					}
				} else if isGoogleDomain && hasH2 {
					targetProtos = []string{"h2", "http/1.1"}
				} else {
					// Fallback to what was requested in the Intercept call, or the client's own support
					if len(protos) > 0 {
						targetProtos = protos
					} else {
						targetProtos = hello.SupportedProtos
					}
				}
			} else {
				// If NO ALPN extension was sent by client...
				// For Google domains, we MUST NOT send NextProtos if the client didn't send ALPN.
				if isGoogleDomain {
					targetProtos = nil
				} else if t.ForceHTTP11 {
					// Even if client didn't send ALPN, if we force H1.1, some strict clients might
					// still work if they fallback to H1.1 by default.
					targetProtos = []string{"http/1.1"}
				} else {
					// Otherwise, we MUST return nil for NextProtos
					// otherwise many clients will EOF immediately due to protocol violation.
					targetProtos = nil
				}
			}

			minVer := uint16(ctls.VersionTLS10)
			maxVer := uint16(ctls.VersionTLS13)

			config := &ctls.Config{
				Certificates:       certs,
				NextProtos:         targetProtos,
				MinVersion:         minVer,
				MaxVersion:         maxVer,
				InsecureSkipVerify: true,
				CipherSuites: []uint16{
					ctls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					ctls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					ctls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					ctls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					ctls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					ctls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				},
				CurvePreferences: []ctls.CurveID{
					ctls.X25519,
					ctls.CurveP256,
				},
				PreferServerCipherSuites: true,
			}

			if t.UseSessionTicket {
				config.SessionTicketKey = t.SessionTicketKey
			}

			return config, nil
		},
	}

	// Set a deadline for the handshake (generous to allow slow clients and avoid EOF)
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// 3. Wrap the connection with TLS
	tlsConn := ctls.Server(conn, config)
	startTime := time.Now()
	if t.Verbose {
		logger.Printf("[TLS] Starting handshake for %s from %s (ALPN: %v)...\n", hostname, conn.RemoteAddr(), protos)
	}

	err = tlsConn.Handshake()
	if err != nil {
		duration := time.Since(startTime)
		// More detailed error logging for EOF and other failures
		errorMsg := err.Error()
		if errorMsg == "EOF" {
			logger.Printf("[TLS] ❌ Handshake EOF for %s after %v. Likely client rejected cert or protocol.\n", hostname, duration)
		} else {
			logger.Printf("[TLS] ❌ Handshake failed for %s: %v (after %v)\n", hostname, err, duration)
		}
		return nil, logger.Errorf("TLS handshake failed for %s: %v", hostname, err)
	}

	cs := tlsConn.ConnectionState()
	if t.Verbose {
		logger.Printf("[TLS] ✅ Handshake success for %s (Negotiated: %s, Version: %x, Cipher: %x)\n",
			hostname, cs.NegotiatedProtocol, cs.Version, cs.CipherSuite)
	}

	// 4. Clear the deadline after successful handshake
	conn.SetDeadline(time.Time{})

	return tlsConn, nil
}

func (t *TLSInterceptor) HandleMITM(src net.Conn, targetAddr string, hostname string, protos []string, tunnel *engine.TunnelConfig, connInfo *engine.ConnInfo) error {
	// Ad-Blocking Layer 2 (Safety check)
	if res, matches := adblock.GetEngine().Match("", hostname); matches {
		return logger.Errorf("blocked ad domain: %s (%s)", hostname, res.Reason)
	}

	// Trigger OnConnect if not already handled
	if connInfo != nil {
		if cfg := t.engine.OnConnect(connInfo); cfg != nil {
			tunnel = cfg
		}
	}

	// 0. Peek SNI if hostname is an IP (local DNS resolution by client)
	originalHostname := hostname
	var peekedPayload []byte
	if net.ParseIP(hostname) != nil || hostname == "" {
		_ = src.SetReadDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 5)
		if _, err := io.ReadFull(src, header); err == nil && header[0] == 22 {
			recordLen := int(binary.BigEndian.Uint16(header[3:5]))
			if recordLen > 0 && recordLen < 16384 {
				body := make([]byte, recordLen)
				if _, err := io.ReadFull(src, body); err == nil {
					peekedPayload = append(header, body...)
					if ch, err := ParseClientHello(peekedPayload); err == nil && ch.SNI != "" {
						hostname = ch.SNI
						if t.Verbose {
							logger.Printf("[TLS] 💡 Recovered hostname from SNI: %s (was %s)\n", hostname, originalHostname)
						}
						// Update ALPN if found in ClientHello
						if len(ch.ALPN) > 0 {
							protos = ch.ALPN
						}
					}
				}
			}
		}
		_ = src.SetReadDeadline(time.Time{})

		// If hostname was recovered from SNI, re-evaluate proxy routing
		if hostname != originalHostname && connInfo != nil {
			// Update Dest with new hostname (keep original port)
			_, port, _ := net.SplitHostPort(targetAddr)
			if port == "" {
				port = "443"
			}
			newTarget := net.JoinHostPort(hostname, port)
			connInfo.Dest = newTarget

			if t.Verbose {
				logger.Printf("[TLS] 🔄 Re-triggering OnConnect for %s (discovered SNI)\n", newTarget)
			}
			if cfg := t.engine.OnConnect(connInfo); cfg != nil {
				tunnel = cfg
			}
		}
	}

	// If we peeked, we MUST wrap 'src' in a PeekedConn for Intercept() to work
	var effectiveSrc net.Conn = src
	if len(peekedPayload) > 0 {
		effectiveSrc = &PeekedConn{Conn: src, Data: peekedPayload}
	}

	// Strategy: Dial REAL target first to capture its certificate and ALPN.
	// This ensures the Intercept call to the client uses a perfectly mirrored cert template.
	hostnameOnly := hostname
	if h, _, err := net.SplitHostPort(targetAddr); err == nil {
		hostnameOnly = h
	}

	// ALWAYS resolve safe to avoid infinite loops if hosts file is redirected to 127.0.0.1
	realIP, err := t.resolveSafe(context.Background(), hostnameOnly)
	if err != nil {
		return logger.Errorf("failed to resolve %s safely: %w", hostnameOnly, err)
	}

	dialAddr := net.JoinHostPort(realIP, "443")
	if t.Verbose {
		logger.Printf("[TLS] 🎯 Resolved %s to real IP: %s (bypassing hosts file)\n", hostnameOnly, realIP)
	}

	// LOOP PROTECTION: If dialAddr resolves to localhost, we are in an infinite loop!
	if strings.Contains(dialAddr, "127.0.0.1:") || strings.Contains(dialAddr, "[::1]:") {
		return logger.Errorf("❌ MITM LOOP DETECTED for %s: Target resolves to %s (hosts file redirect?). Stopping to prevent crash.", hostname, dialAddr)
	}

	// Double check: if dialAddr matches the local address of this interceptor, it's a loop
	if src != nil && src.LocalAddr() != nil {
		if dialAddr == src.LocalAddr().String() {
			return logger.Errorf("❌ MITM DIRECT LOOP DETECTED for %s: Target %s matches local listener address.", hostname, dialAddr)
		}
	}

	// 1. Connect to REAL target using UniversalDialer if tunnel is set
	var dstTls net.Conn

	if tunnel != nil {
		Dialer := &proxy.UniversalDialer{Tunnel: tunnel}
		// Use the resolved real IP (dialAddr) to avoid domain-based restrictions
		// on upstream proxies. We already resolved the IP via resolveSafe().
		proxyTarget := dialAddr
		upstreamConn, err := Dialer.Dial("tcp", proxyTarget)
		if err != nil {
			return logger.Errorf("failed to dial upstream tunnel: %w\n", err)
		}

		// Use native crypto/tls for tunnel connections (fingerprint spoofing is
		// unnecessary through a tunnel and utls can cause protocol issues).
		upstreamProtos := protos
		if t.ForceHTTP11 {
			upstreamProtos = []string{"http/1.1"}
		}
		tunnelTLSConf := &ctls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true,
			NextProtos:         upstreamProtos,
			ClientSessionCache: t.nativeCache,
		}
		tlsConn := ctls.Client(upstreamConn, tunnelTLSConf)
		if err := tlsConn.Handshake(); err != nil {
			upstreamConn.Close()
			return logger.Errorf("TLS handshake failed over tunnel: %w", err)
		}
		dstTls = tlsConn
	} else {
		upstreamProtos := protos
		if t.ForceHTTP11 {
			upstreamProtos = []string{"http/1.1"}
		}

		if t.isGoogle(hostname) {
			// Google is sensitive to uTLS fingerprints. Use native crypto/tls for maximum compatibility.
			conf := &ctls.Config{
				ServerName:         hostname,
				InsecureSkipVerify: true,
				NextProtos:         upstreamProtos,
				ClientSessionCache: t.nativeCache,
			}
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			dstTls, err = ctls.DialWithDialer(dialer, "tcp4", dialAddr, conf)
			if err != nil {
				return logger.Errorf("failed to connect to google target %s (%s) via native TLS: %w", dialAddr, hostname, err)
			}
		} else {
			// For non-google, we use our specialized TLSDialer which defaults to Chrome 120
			dialer, err := network.NewTLSDialer(network.ProfileChrome120, network.TCPProfileWindows, "", nil)
			if err != nil {
				return logger.Errorf("failed to create TLS dialer: %w", err)
			}
			dialer.Insecure = true
			dialer.ClientSessionCache = t.sessionCache

			if t.ForceHTTP11 {
				// Override profile to avoid H2 negotiation if forced
				dialer.Profile = network.ProfileNative
				upstreamProtos = []string{"http/1.1"}
			}

			dstTls, err = dialer.DialTLSWithServerNameALPN("tcp", dialAddr, hostname, upstreamProtos)
			if err != nil {
				return logger.Errorf("failed to connect to target %s (%s): %w", dialAddr, hostname, err)
			}
		}
	}
	defer dstTls.Close()

	// 2. Capture and update certificate template from real server
	var negotiated string
	// Check for ConnectionState to get NegotiatedProtocol (ALPN)
	if t.Verbose {
		logger.Printf("[TLS] 🔍 Checking ConnectionState for %T\n", dstTls)
	}

	if tc, ok := dstTls.(interface{ ConnectionState() ctls.ConnectionState }); ok {
		state := tc.ConnectionState()
		negotiated = state.NegotiatedProtocol
		if t.Verbose {
			logger.Printf("[TLS] ✅ ConnectionState (native) for %s: PeerCerts=%d, ALPN=%q\n", hostname, len(state.PeerCertificates), negotiated)
		}
		if len(state.PeerCertificates) > 0 {
			t.templateMu.Lock()
			t.certTemplate[hostname] = state.PeerCertificates[0]
			t.templateMu.Unlock()
		}
	} else if tc, ok := dstTls.(interface{ ConnectionState() utls.ConnectionState }); ok {
		state := tc.ConnectionState()
		negotiated = state.NegotiatedProtocol
		if t.Verbose {
			logger.Printf("[TLS] ✅ ConnectionState (uTLS) for %s: PeerCerts=%d, ALPN=%q\n", hostname, len(state.PeerCertificates), negotiated)
		}
		if len(state.PeerCertificates) > 0 {
			t.templateMu.Lock()
			t.certTemplate[hostname] = state.PeerCertificates[0]
			t.templateMu.Unlock()
		}
	} else {
		if t.Verbose {
			logger.Printf("[TLS] ⚠️  Could not obtain ConnectionState for %T (no matching interface)\n", dstTls)
		}
	}

	// 3. Hijack source with our own certificate using the updated template
	// We pass the upstream's negotiated protocol to Intercept to guide selection
	interceptProtos := protos
	if negotiated != "" {
		interceptProtos = []string{negotiated}
	}

	srcTls, err := t.Intercept(effectiveSrc, hostname, interceptProtos)
	if err != nil {
		logger.Printf("[TLS] Intercept failed: %v\n", err)
		return err
	}
	defer srcTls.Close()

	if t.Verbose {
		logger.Printf("[TLS] Transparent MITM active: %s <-> %s (%s, Proto: %s)\n", src.RemoteAddr(), dialAddr, hostname, negotiated)
	}

	// Logging result
	if t.Verbose {
		logger.Printf("[TLS] 🔓 MITM Handshake success for %s. Negotiated: %q (ALPN Sync: %v)\n", hostname, negotiated, negotiated != "")
	}

	// Relay the decrypted traffic through the engine
	// Use hostname if targetAddr is empty (e.g. when called from SNIListener)
	relayTarget := targetAddr
	if relayTarget == "" {
		relayTarget = net.JoinHostPort(hostname, "443")
	}
	relay := proxy.NewRelay(t.engine, relayTarget, true)
	if connInfo != nil {
		relay.RegisterConn(connInfo)
	}
	relay.Start(srcTls, dstTls)
	return nil
}

// PeekedConn wraps a net.Conn and replays peeked data before reading forward.
type PeekedConn struct {
	net.Conn
	Data []byte
	Off  int
}

func (c *PeekedConn) Read(b []byte) (int, error) {
	if c.Off < len(c.Data) {
		n := copy(b, c.Data[c.Off:])
		c.Off += n
		return n, nil
	}
	return c.Conn.Read(b)
}

func (t *TLSInterceptor) isGoogle(hostname string) bool {
	hostname = strings.ToLower(hostname)
	googleDomains := []string{
		"googleapis.com", "google.com", "gstatic.com", "googleusercontent.com",
		"ggpht.com", "google-analytics.com", "googletagmanager.com",
		"googleadservices.com", "googlesyndication.com",
		"google.co.id", "google.com.sg",
	}
	for _, d := range googleDomains {
		if hostname == d || strings.HasSuffix(hostname, "."+d) {
			return true
		}
	}
	return false
}

func (t *TLSInterceptor) resolveSafe(ctx context.Context, host string) (string, error) {
	// 1. Check cache first
	if ip, ok := t.ResolvedIPs[host]; ok {
		return ip, nil
	}

	// 2. Use private resolver to bypass system hosts file
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			// Try Google and Cloudflare DNS directly
			publicDNS := []string{"8.8.8.8:53", "1.1.1.1:53"}
			var lastErr error
			for _, dns := range publicDNS {
				conn, err := d.DialContext(ctx, "udp", dns)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}

	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}

	for _, ip := range ips {
		if ipv4 := ip.IP.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	if len(ips) > 0 {
		return ips[0].IP.String(), nil
	}

	return "", fmt.Errorf("no IP found for %s", host)
}
