package capture

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/protocol/tls"
	"github.com/bacot120211/netkit-go/pkg/proxy"
	"github.com/bacot120211/netkit-go/pkg/security"
)

// HTTPProxyListener is an HTTP/HTTPS MITM proxy listener.
// Browser harus set proxy ke addr ini (satu port untuk HTTP dan HTTPS).
type HTTPProxyListener struct {
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

func NewHTTPProxyListener(addr string, ca *tls.CA, e engine.Engine, resolvedIPs map[string]string) *HTTPProxyListener {
	tlsInt := tls.NewTLSInterceptor(ca, e)
	tlsInt.ResolvedIPs = resolvedIPs
	return &HTTPProxyListener{
		addr:   addr,
		engine: e,
		tlsInt: tlsInt,
	}
}

func (l *HTTPProxyListener) Listen() error {
	listener, err := net.Listen("tcp", l.addr)
	if err != nil {
		return err
	}
	l.listener = listener
	return nil
}

func (l *HTTPProxyListener) Serve(ctx context.Context) error {
	if l.listener == nil {
		if err := l.Listen(); err != nil {
			return err
		}
	}
	defer l.listener.Close()

	logger.Printf("[HTTPProxy] 🌐 MITM Proxy listening on %s — set browser proxy to this address\n", l.addr)
	l.setCRLUrl()

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
				logger.Printf("[HTTPProxy] Accept error: %v\n", err)
				continue
			}
		}
		logger.Printf("[HTTPProxy] 🔌 New connection from %s\n", conn.RemoteAddr())
		go l.handleConn(conn)
	}
}

func (l *HTTPProxyListener) setCRLUrl() {
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
	logger.Printf("[HTTPProxy] 📜 CRL Distribution Point set to: %s\n", crlURL)
}

func (l *HTTPProxyListener) Close() error {
	if l.listener != nil {
		return l.listener.Close()
	}
	return nil
}

func (l *HTTPProxyListener) SetTunnel(tc *engine.TunnelConfig) {
	l.tunnel = tc
}

func (l *HTTPProxyListener) handleConn(src net.Conn) {
	defer src.Close()
	remoteAddr := src.RemoteAddr().String()
	localAddr := src.LocalAddr().String()
	localHost, _, _ := net.SplitHostPort(localAddr)

	// Set read deadline agar tidak block selamanya
	_ = src.SetDeadline(time.Now().Add(30 * time.Second))

	// 0. Security: Bruteforce Check
	if l.Limiter != nil && !l.Limiter.IsAllowed(remoteAddr) {
		logger.Warnf("[HTTPProxy] 🚫 BANNED IP attempted connection: %s\n", remoteAddr)
		return
	}

	reader := bufio.NewReader(src)
	logger.Printf("[HTTPProxy] 📖 Reading request from %s...\n", remoteAddr)

	hostname := ""
	connInfo := &engine.ConnInfo{
		Type:    "http_proxy",
		Source:  src.RemoteAddr().String(),
		IP:      src.RemoteAddr().String(),
		Through: engine.GetIPType(localHost),
	}

	// Detect SOCKS5 (0x05)
	p, err := reader.Peek(1)
	if err == nil && len(p) > 0 && p[0] == 0x05 {
		logger.Printf("[HTTPProxy] 🧦 SOCKS5 detected on HTTP port from %s\n", remoteAddr)
		HandleSOCKS5Shared(src, reader, l.engine, l.tlsInt, "HTTPProxy-SOCKS", l.tunnel, l.ShouldMITM, l.User, l.Pass, l.Limiter)
		return
	}

	req, err := http.ReadRequest(reader)
	if err != nil {
		logger.Printf("[HTTPProxy] ❌ ReadRequest error from %s: %v\n", remoteAddr, err)
		return
	}

	// CRL Hijack: Serve our own CRL to satisfy SChannel revocation checks
	if req.URL.Path == "/proxy.crl" || req.URL.Path == "/crl" {
		crl, err := l.tlsInt.GetCRL()
		if err == nil {
			logger.Printf("[HTTPProxy] 📜 Serving CRL to %s (Host: %s)\n", remoteAddr, req.Host)
			_, _ = src.Write([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(crl))))
			_, _ = src.Write(crl)
			return
		}
	}

	// Reset deadline setelah baca request
	_ = src.SetDeadline(time.Time{})

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	connInfo.Dest = host

	fmt.Printf("[HTTPProxy] 📨 %s %s from %s\n", req.Method, host, remoteAddr)
	connInfo.Path = req.URL.Path

	// Trigger OnConnect callback in JS
	if cfg := l.engine.OnConnect(connInfo); cfg != nil {
		if strings.ToLower(cfg.Type) == "drop" {
			logger.Printf("[HTTPProxy] 🚫 Connection dropped by OnConnect for %s\n", remoteAddr)
			return
		}
		l.tunnel = cfg
	}

	// Auth Check
	if l.User != "" || l.Pass != "" {
		auth := req.Header.Get("Proxy-Authorization")
		if auth == "" {
			logger.Printf("[HTTPProxy] ❌ Missing Proxy-Authorization from %s\n", remoteAddr)
			_, _ = src.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"NetKit\"\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		// Expect "Basic base64(user:pass)"
		prefix := "Basic "
		if !strings.HasPrefix(auth, prefix) {
			_, _ = src.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
		if err != nil || string(decoded) != l.User+":"+l.Pass {
			logger.Printf("[HTTPProxy] ❌ Invalid Proxy-Authorization from %s\n", remoteAddr)
			if l.Limiter != nil {
				l.Limiter.RecordFailure(remoteAddr)
			}
			_, _ = src.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			return
		}
		if l.Limiter != nil {
			l.Limiter.RecordSuccess(remoteAddr)
		}
	}

	if req.Method == http.MethodConnect {
		// HTTPS CONNECT tunnel
		hostname = host
		if h, _, err2 := net.SplitHostPort(host); err2 == nil {
			hostname = h
		}

		// Confirm tunnel established ke browser
		_, _ = src.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		logger.Printf("[HTTPProxy] 🔒 CONNECT %s (hostname=%s)\n", host, hostname)
		if l.ShouldMITM == nil || l.ShouldMITM(hostname) {
			logger.Printf("[HTTPProxy] 🔓 Handing off %s to MITM Interceptor\n", host)
			_ = l.tlsInt.HandleMITM(src, host, hostname, nil, l.tunnel, connInfo)
		} else {
			logger.Printf("[HTTPProxy] ⏩ Skipping MITM for %s (not in sniff list)\n", host)
			dialer := &proxy.UniversalDialer{Tunnel: l.tunnel}
			dst, err := dialer.Dial("tcp", host)
			if err == nil {
				defer dst.Close()
				relay := proxy.NewRelay(l.engine, hostname, false)
				relay.RegisterConn(connInfo)
				relay.Start(src, dst)
			} else {
				logger.Printf("[HTTPProxy] ❌ Passthrough dial failed: %v\n", err)
			}
		}
		logger.Printf("[HTTPProxy] 🔒 CONNECT %s done\n", host)
		return
	}

	// Plain HTTP
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}
	connInfo.Dest = host

	logger.Printf("[HTTPProxy] 🌍 HTTP %s → %s\n", req.Method, host)

	// Ingest the initial request
	payload := []byte(req.Method + " " + req.URL.String() + " " + req.Proto + "\r\n")
	srcHost, srcPortStr, _ := net.SplitHostPort(src.RemoteAddr().String())
	var srcPort uint16
	fmt.Sscanf(srcPortStr, "%d", &srcPort)

	r := &engine.Packet{
		ID:         uint64(time.Now().UnixNano()),
		Timestamp:  time.Now().Unix(),
		Source:     srcHost,
		SourcePort: srcPort,
		Dest:       host,
		DestPort:   80,
		Protocol:   "HTTP",
		Payload:    payload,
		Metadata: map[string]interface{}{
			"Hostname":  host,
			"Decrypted": false,
			"Direction": "REQUEST",
		},
		Conn: connInfo,
	}
	l.engine.Ingest(r)

	dialer := &proxy.UniversalDialer{Tunnel: l.tunnel}
	dst, err := dialer.Dial("tcp", host)
	if err != nil {
		logger.Printf("[HTTPProxy] ❌ Dial %s error: %v\n", host, err)
		_, _ = src.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	defer dst.Close()

	// Tulis request pertama ke target
	if err := req.WriteProxy(dst); err != nil {
		logger.Printf("[HTTPProxy] ❌ WriteProxy error: %v\n", err)
		return
	}

	// Relay bi-directional traffic to ensure RESPONSES are hooked
	relay := proxy.NewRelay(l.engine, host, false) // Plain HTTP
	relay.RegisterConn(connInfo)
	relay.Start(src, dst)

	logger.Printf("[HTTPProxy] 🌍 HTTP %s done\n", host)
}

// relayHTTPRequests forward request HTTP lanjutan (keep-alive) sambil inject ke engine.
func (l *HTTPProxyListener) relayHTTPRequests(reader *bufio.Reader, src, dst net.Conn, host string) {
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		if err := req.WriteProxy(dst); err != nil {
			return
		}
		payload := []byte(req.Method + " " + req.URL.String() + " HTTP/1.1\r\n")
		srcHost, srcPortStr, _ := net.SplitHostPort(src.RemoteAddr().String())
		dstHost, dstPortStr, _ := net.SplitHostPort(dst.RemoteAddr().String())
		var srcPort, dstPort uint16
		fmt.Sscanf(srcPortStr, "%d", &srcPort)
		fmt.Sscanf(dstPortStr, "%d", &dstPort)
		p := &engine.Packet{
			ID:         uint64(time.Now().UnixNano()),
			Timestamp:  time.Now().Unix(),
			Source:     srcHost,
			SourcePort: srcPort,
			Dest:       dstHost,
			DestPort:   dstPort,
			Protocol:   "HTTP",
			Payload:    payload,
			Metadata: map[string]interface{}{
				"Hostname":  host,
				"Decrypted": false,
			},
		}
		l.engine.Process(p, nil)
	}
}
