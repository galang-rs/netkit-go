package proxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	socks5proxy "golang.org/x/net/proxy"
)

// UniversalDialer handles connections through various tunnel types (Proxy, WG).
type UniversalDialer struct {
	Tunnel *engine.TunnelConfig
}

func (d *UniversalDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *UniversalDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.Tunnel == nil || d.Tunnel.Type == "" {
		dialer := net.Dialer{Timeout: 10 * time.Second}
		return dialer.DialContext(ctx, network, address)
	}

	switch strings.ToLower(d.Tunnel.Type) {
	case "drop":
		return nil, fmt.Errorf("connection dropped by onConnect")
	case "proxy", "socks5", "socks5h", "http", "https":
		return dialUpstreamProxy(ctx, d.Tunnel.URL, address)
	case "ssh":
		return dialUpstreamSSH(ctx, d.Tunnel.SSH, address)
	case "wg":
		if d.Tunnel.WGConfig != "" {
			return GetWGManager().DialContext(ctx, network, address, d.Tunnel.WGConfig)
		}
		return nil, fmt.Errorf("WireGuard config missing in TunnelConfig")
	default:
		dialer := net.Dialer{Timeout: 10 * time.Second}
		return dialer.DialContext(ctx, network, address)
	}
}

func dialUpstreamProxy(ctx context.Context, proxyURLStr, targetAddr string) (net.Conn, error) {
	pURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %v", err)
	}

	scheme := strings.ToLower(pURL.Scheme)
	timeout := 10 * time.Second

	switch {
	case scheme == "socks5" || scheme == "socks5h":
		var auth *socks5proxy.Auth
		if pURL.User != nil {
			p, _ := pURL.User.Password()
			auth = &socks5proxy.Auth{
				User:     pURL.User.Username(),
				Password: p,
			}
			logger.Printf("[Proxy] 🛡️  SOCKS5 Auth Debug: User=%q, PassLen=%d, Target=%s\n", auth.User, len(auth.Password), targetAddr)
			// Log hex of first 4 bytes of pass to check for encoding issues
			passHex := ""
			for i := 0; i < len(auth.Password) && i < 4; i++ {
				passHex += fmt.Sprintf("%02x ", auth.Password[i])
			}
			logger.Printf("[Proxy] 🛡️  Pass Hex: %s\n", passHex)
		}
		logger.Printf("[Proxy] 🚀 Dialing %s via SOCKS5 %s\n", targetAddr, pURL.Host)
		dialer, err := socks5proxy.SOCKS5("tcp", pURL.Host, auth, &net.Dialer{Timeout: timeout})
		if err != nil {
			return nil, fmt.Errorf("socks5 setup error: %w", err)
		}
		return dialer.Dial("tcp", targetAddr)

	case scheme == "http" || scheme == "https":
		// Simple HTTP CONNECT proxy implementation
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", pURL.Host)
		if err != nil {
			return nil, err
		}

		req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
		_, err = conn.Write([]byte(req))
		if err != nil {
			conn.Close()
			return nil, err
		}

		// Wait for 200 OK
		resp := make([]byte, 1024)
		n, err := conn.Read(resp)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if !strings.Contains(string(resp[:n]), "200") {
			conn.Close()
			return nil, fmt.Errorf("proxy CONNECT failed: %s", string(resp[:n]))
		}
		return conn, nil

	default:
		return nil, fmt.Errorf("unsupported upstream proxy scheme: %s", scheme)
	}
}
