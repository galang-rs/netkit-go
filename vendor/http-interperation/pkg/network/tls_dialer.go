package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/proxy"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"

	utls "github.com/bogdanfinn/utls"
)

// TLSDialer creates TLS connections with custom fingerprints
type TLSDialer struct {
	Profile            *TLSProfile
	NetDialer          *net.Dialer
	tcpProfile         *TCPProfile
	proxyAddress       string
	proxyAuth          *proxy.Auth
	Insecure           bool
	ClientSessionCache utls.ClientSessionCache
	MaxVersion         uint16
}

// NewTLSDialer creates a new TLS dialer with the given profile
func NewTLSDialer(profile *TLSProfile, tcpProfile *TCPProfile, proxyAddr string, proxyAuth *proxy.Auth) (*TLSDialer, error) {
	dialer := &TLSDialer{
		Profile:      profile,
		tcpProfile:   tcpProfile,
		MaxVersion:   utls.VersionTLS13,
		proxyAddress: proxyAddr,
		proxyAuth:    proxyAuth,
		NetDialer: &net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					// Use public DNS servers directly to bypass broken system DNS
					// (system DNS may be unreachable due to WireGuard routing or hosts file)
					publicDNS := []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}
					d := net.Dialer{
						Timeout: time.Second * 3,
					}
					for _, dns := range publicDNS {
						conn, err := d.DialContext(ctx, "udp4", dns)
						if err == nil {
							return conn, nil
						}
					}
					// Last resort: try the original system DNS address
					return d.DialContext(ctx, "udp4", address)
				},
			},
		},
	}

	// Apply TCP profile if provided
	if tcpProfile != nil {
		if tcpProfile.SourcePort > 0 {
			dialer.NetDialer.LocalAddr = &net.TCPAddr{
				Port: tcpProfile.SourcePort,
			}
		}
		dialer.NetDialer.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set TTL
				if tcpProfile.TTL > 0 {
					_ = setSocketTTL(fd, tcpProfile.TTL)
				}
				// Set Window Size
				if tcpProfile.WindowSize > 0 {
					_ = setSocketWindowSize(fd, tcpProfile.WindowSize)
				}
			})
		}
	}

	return dialer, nil
}

// DialTLS creates a TLS connection with custom fingerprint
func (d *TLSDialer) DialTLS(network, addr string) (net.Conn, error) {
	return d.DialTLSContext(context.Background(), network, addr)
}

// DialTLSWithServerName creates a TLS connection with custom fingerprint and explicit ServerName
func (d *TLSDialer) DialTLSWithServerName(network, addr, serverName string) (net.Conn, error) {
	return d.dialTLSContextWithALPN(context.Background(), network, addr, serverName, nil)
}

// DialTLSWithServerNameALPN creates a TLS connection with custom fingerprint, explicit ServerName and ALPN protos
func (d *TLSDialer) DialTLSWithServerNameALPN(network, addr, serverName string, protos []string) (net.Conn, error) {
	return d.dialTLSContextWithALPN(context.Background(), network, addr, serverName, protos)
}

// DialTLSContext creates a TLS connection with custom fingerprint and context
func (d *TLSDialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Extract hostname for SNI as default
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return d.dialTLSContext(ctx, network, addr, host)
}

func (d *TLSDialer) dialTLSContext(ctx context.Context, network, addr, serverName string) (net.Conn, error) {
	return d.dialTLSContextWithALPN(ctx, network, addr, serverName, nil)
}

func (d *TLSDialer) dialTLSContextWithALPN(ctx context.Context, network, addr, serverName string, protos []string) (net.Conn, error) {
	// Force IPv4
	dialNetwork := network
	if dialNetwork == "tcp" {
		dialNetwork = "tcp4"
	}

	var rawConn net.Conn
	var err error

	if d.proxyAddress != "" {
		dialer, err := proxy.SOCKS5("tcp4", d.proxyAddress, d.proxyAuth, d.NetDialer)
		if err != nil {
			return nil, fmt.Errorf("failed to create proxy dialer: %w", err)
		}

		if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
			rawConn, err = contextDialer.DialContext(ctx, dialNetwork, addr)
		} else {
			rawConn, err = dialer.Dial(dialNetwork, addr)
		}
	} else {
		rawConn, err = d.NetDialer.DialContext(ctx, dialNetwork, addr)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	// Create uTLS connection with custom fingerprint
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// Trust local MITM CA if exists (handling first-launch trust issue)
	if certData, err := os.ReadFile("ca.crt"); err == nil {
		rootCAs.AppendCertsFromPEM(certData)
	}

	if protos == nil {
		protos = []string{"h2", "http/1.1"}
	}

	sessionCache := d.ClientSessionCache
	if sessionCache == nil {
		sessionCache = utls.NewLRUClientSessionCache(32)
	}

	tlsConfig := &utls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     true, // Forced: menerima semua cert
		RootCAs:                rootCAs,
		MinVersion:             tls.VersionTLS10,
		MaxVersion:             d.MaxVersion,
		NextProtos:             protos,
		SessionTicketsDisabled: false,
		ClientSessionCache:     sessionCache,
	}

	// Create uTLS connection with custom fingerprint
	uConn := utls.UClient(rawConn, tlsConfig, utls.HelloCustom, false, true, true)

	// Generate a fresh spec with consistent extension order for JA3 consistency.
	// NewOrderedSpec creates new extension instances each time (no shared state)
	// but re-sorts them to match the cached extension order.
	if spec, err := d.Profile.NewOrderedSpec(); err == nil {
		if err := uConn.ApplyPreset(spec); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("failed to apply uTLS spec: %w", err)
		}
	}

	// Perform TLS handshake
	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed for %s: %w", serverName, err)
	}

	return uConn, nil
}

// AdaptiveTransport handles both HTTP/1.1 and HTTP/2 based on ALPN negotiation
type AdaptiveTransport struct {
	dialer *TLSDialer
	h1     *http.Transport
	h2     *http2.Transport
}

// NewAdaptiveTransport creates a transport that adapts to the negotiated protocol
func NewAdaptiveTransport(profile *TLSProfile, tcpProfile *TCPProfile, proxyAddr string, proxyAuth *proxy.Auth) (*AdaptiveTransport, error) {
	dialer, err := NewTLSDialer(profile, tcpProfile, proxyAddr, proxyAuth)
	if err != nil {
		return nil, err
	}

	// HTTP/1.1 transport
	h1Transport := &http.Transport{
		DialTLSContext: dialer.DialTLSContext,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.NetDialer.DialContext(ctx, "tcp4", addr)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
	}

	// Configure HTTP/2
	h2Transport, err := http2.ConfigureTransports(h1Transport)
	if err != nil {
		return nil, fmt.Errorf("failed to configure h2 transport: %w", err)
	}

	// Apply H2 Settings from profile
	h2Transport.InitialWindowSize = profile.InitialWindowSize
	h2Transport.HeaderTableSize = profile.HeaderTableSize

	pushValue := uint32(0)
	if profile.EnablePush {
		pushValue = 1
	}

	h2Transport.Settings = map[http2.SettingID]uint32{
		http2.SettingEnablePush:           pushValue,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    profile.InitialWindowSize,
		http2.SettingMaxFrameSize:         profile.MaxFrameSize,
	}

	if profile.MaxHeaderListSize > 0 {
		h2Transport.Settings[http2.SettingMaxHeaderListSize] = profile.MaxHeaderListSize
	}

	h2Transport.StrictMaxConcurrentStreams = true

	if len(profile.PseudoHeaderOrder) > 0 {
		h2Transport.PseudoHeaderOrder = profile.PseudoHeaderOrder
	} else {
		// Default to Chrome order if not specified
		h2Transport.PseudoHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}
	}

	return &AdaptiveTransport{
		dialer: dialer,
		h1:     h1Transport,
		h2:     h2Transport,
	}, nil
}

// RoundTrip implements http.RoundTripper
func (t *AdaptiveTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// fhttp's Transport will automatically use H2 if it was configured via ConfigureTransports
	// and ALPN negotiated h2.
	return t.h1.RoundTrip(req)
}

// CloseIdleConnections closes idle connections on both transports
func (t *AdaptiveTransport) CloseIdleConnections() {
	t.h1.CloseIdleConnections()
	if t.h2 != nil {
		t.h2.CloseIdleConnections()
	}
}

// DialContextFunc is a function type for custom dial contexts (e.g. WireGuard tnet.DialContext)
type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// NewAdaptiveTransportWithDialer creates a transport using a custom DialContext (bypasses direct connection)
func NewAdaptiveTransportWithDialer(profile *TLSProfile, tcpProfile *TCPProfile, dialFunc DialContextFunc, proxyAddr string, proxyAuth *proxy.Auth) (*AdaptiveTransport, error) {
	dialer, err := NewTLSDialer(profile, tcpProfile, proxyAddr, proxyAuth)
	if err != nil {
		return nil, err
	}

	// HTTP/1.1 transport with custom DialContext
	h1Transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Use dialFunc for the raw connection (through WireGuard TUN)
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}

			rawConn, err := dialFunc(ctx, network, addr)
			if err != nil {
				return nil, fmt.Errorf("failed to dial via TUN: %w", err)
			}

			// Create uTLS connection with custom fingerprint
			rootCAs, _ := x509.SystemCertPool()
			if rootCAs == nil {
				rootCAs = x509.NewCertPool()
			}
			if certData, err := os.ReadFile("ca.crt"); err == nil {
				rootCAs.AppendCertsFromPEM(certData)
			}

			tlsConfig := &utls.Config{
				ServerName:             host,
				InsecureSkipVerify:     true, // Forced: menerima semua cert
				RootCAs:                rootCAs,
				MinVersion:             0x0301, // TLS 1.0
				MaxVersion:             0x0304, // TLS 1.3
				NextProtos:             []string{"h2", "http/1.1"},
				SessionTicketsDisabled: false,
				ClientSessionCache:     utls.NewLRUClientSessionCache(32),
			}

			// Create uTLS connection with custom fingerprint
			uConn := utls.UClient(rawConn, tlsConfig, utls.HelloCustom, false, true, true)

			// Generate a fresh spec with cached extension order
			if spec, err := dialer.Profile.NewOrderedSpec(); err == nil {
				if err := uConn.ApplyPreset(spec); err != nil {
					rawConn.Close()
					return nil, fmt.Errorf("failed to apply uTLS spec: %w", err)
				}
			} else {
				// Fallback to ID-based setup
				uConn = utls.UClient(rawConn, tlsConfig, dialer.Profile.ClientHello, false, true, true)
			}

			if err := uConn.Handshake(); err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("TLS handshake failed: %w", err)
			}

			return uConn, nil
		},
		DialContext:           dialFunc,
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
	}

	// Configure HTTP/2
	h2Transport, err := http2.ConfigureTransports(h1Transport)
	if err != nil {
		return nil, fmt.Errorf("failed to configure h2 transport: %w", err)
	}

	h2Transport.InitialWindowSize = profile.InitialWindowSize
	h2Transport.HeaderTableSize = profile.HeaderTableSize

	pushValue := uint32(0)
	if profile.EnablePush {
		pushValue = 1
	}

	h2Transport.Settings = map[http2.SettingID]uint32{
		http2.SettingEnablePush:           pushValue,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    profile.InitialWindowSize,
		http2.SettingMaxFrameSize:         profile.MaxFrameSize,
	}

	if profile.MaxHeaderListSize > 0 {
		h2Transport.Settings[http2.SettingMaxHeaderListSize] = profile.MaxHeaderListSize
	}

	h2Transport.StrictMaxConcurrentStreams = true

	if len(profile.PseudoHeaderOrder) > 0 {
		h2Transport.PseudoHeaderOrder = profile.PseudoHeaderOrder
	} else {
		h2Transport.PseudoHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}
	}

	return &AdaptiveTransport{
		dialer: dialer,
		h1:     h1Transport,
		h2:     h2Transport,
	}, nil
}

// NewTLSTransport creates an HTTP transport with custom TLS fingerprint (HTTP/1.1 only)
func NewTLSTransport(profile *TLSProfile, tcpProfile *TCPProfile, proxyAddr string, proxyAuth *proxy.Auth) (*http.Transport, error) {
	dialer, err := NewTLSDialer(profile, tcpProfile, proxyAddr, proxyAuth)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		DialTLSContext: dialer.DialTLSContext,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.NetDialer.DialContext(ctx, "tcp4", addr)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          make(map[string]func(authority string, c *utls.Conn) http.RoundTripper), // Disable HTTP/2
	}

	return transport, nil
}

// NewHTTP2Transport creates an HTTP/2 only transport with custom TLS fingerprint
func NewHTTP2Transport(profile *TLSProfile, tcpProfile *TCPProfile, proxyAddr string, proxyAuth *proxy.Auth) (http.RoundTripper, error) {
	return NewAdaptiveTransport(profile, tcpProfile, proxyAddr, proxyAuth)
}
