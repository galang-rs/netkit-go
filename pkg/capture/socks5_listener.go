package capture

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/protocol/tls"
	"github.com/bacot120211/netkit-go/pkg/security"
)

// SOCKS5Listener implements a SOCKS5 proxy server with MITM support.
type SOCKS5Listener struct {
	addr       string
	engine     engine.Engine
	tlsInt     *tls.TLSInterceptor
	listener   net.Listener
	tunnel     *engine.TunnelConfig
	ShouldMITM func(string) bool
	User       string
	Pass       string
	CRLHost    string
	Limiter    *security.BruteforceLimiter
}

func NewSOCKS5Listener(addr string, ca *tls.CA, e engine.Engine, resolvedIPs map[string]string) *SOCKS5Listener {
	tlsInt := tls.NewTLSInterceptor(ca, e)
	tlsInt.ResolvedIPs = resolvedIPs
	tlsInt.Verbose = false
	return &SOCKS5Listener{
		addr:   addr,
		engine: e,
		tlsInt: tlsInt,
	}
}

func (l *SOCKS5Listener) Listen() error {
	listener, err := net.Listen("tcp", l.addr)
	if err != nil {
		return err
	}
	l.listener = listener
	logger.Printf("[SOCKS5] 📍 Bound to %s\n", listener.Addr())
	return nil
}

func (l *SOCKS5Listener) Serve(ctx context.Context) error {
	if l.listener == nil {
		if err := l.Listen(); err != nil {
			return err
		}
	}
	defer l.listener.Close()
	l.setCRLUrl()

	logger.Printf("[SOCKS5] 🛡️  MITM Proxy listening on %s\n", l.addr)

	go func() {
		<-ctx.Done()
		l.listener.Close()
	}()

	for {
		conn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				logger.Printf("[SOCKS5] Accept error: %v\n", err)
				continue
			}
		}
		logger.Printf("[SOCKS5] 🔌 New connection from %s\n", conn.RemoteAddr())
		go l.handleConn(conn)
	}
}

func (l *SOCKS5Listener) Close() error {
	if l.listener != nil {
		return l.listener.Close()
	}
	return nil
}

func (l *SOCKS5Listener) SetTunnel(tc *engine.TunnelConfig) {
	l.tunnel = tc
}

func (l *SOCKS5Listener) setCRLUrl() {
	if l.listener == nil {
		return
	}
	addr := l.listener.Addr().String()
	host := l.CRLHost
	if host == "" {
		// Jika addr adalah ":port", ubah ke GetLocalIP() untuk Windows compatibility
		if strings.HasPrefix(addr, ":") || strings.HasPrefix(addr, "[::]") {
			host = GetLocalIP()
		} else {
			host, _, _ = net.SplitHostPort(addr)
		}
	}
	_, port, _ := net.SplitHostPort(addr)
	crlURL := fmt.Sprintf("http://%s:%s/proxy.crl", host, port)
	l.tlsInt.SetCRLURL(crlURL)
	logger.Printf("[SOCKS5] 📜 CRL Distribution Point set to: %s\n", crlURL)
}

func (l *SOCKS5Listener) handleConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Peek to detect SOCKS5 vs HTTP CRL request
	p, err := reader.Peek(1)
	if err == nil && len(p) > 0 {
		if p[0] != 0x05 {
			// Might be HTTP (GET /proxy.crl)
			req, err := http.ReadRequest(reader)
			if err == nil {
				if req.URL.Path == "/proxy.crl" || req.URL.Path == "/crl" {
					crl, err := l.tlsInt.GetCRL()
					if err == nil {
						logger.Printf("[SOCKS5] 📜 Serving CRL to %s\n", conn.RemoteAddr())
						_, _ = conn.Write([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(crl))))
						_, _ = conn.Write(crl)
						return
					}
				}
			}
			// If not CRL or failed to read, just drop it or return error
			return
		}
	}

	HandleSOCKS5Shared(conn, reader, l.engine, l.tlsInt, "SOCKS5", l.tunnel, l.ShouldMITM, l.User, l.Pass, l.Limiter)
}
