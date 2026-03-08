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
	"github.com/bacot120211/netkit-go/pkg/proxy"
)

// HTTPListener listens for plain HTTP connections.
// It peeks at the Host header to determine the target for transparent redirection.
type HTTPListener struct {
	addr        string
	engine      engine.Engine
	ResolvedIPs map[string]string
}

func NewHTTPListener(addr string, e engine.Engine, resolvedIPs map[string]string) *HTTPListener {
	return &HTTPListener{
		addr:        addr,
		engine:      e,
		ResolvedIPs: resolvedIPs,
	}
}

func (l *HTTPListener) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("[HTTP] failed to listen on %s: %w", l.addr, err)
	}
	defer listener.Close()

	logger.Printf("[HTTP] 🌍 Transparent Listener active on %s\n", l.addr)

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
		go l.handleConn(conn)
	}
}

func (l *HTTPListener) handleConn(src net.Conn) {
	defer src.Close()

	// Read request to find Host header
	reader := bufio.NewReader(src)
	req, err := http.ReadRequest(reader)
	if err != nil {
		logger.Printf("[HTTP] ❌ ReadRequest error: %v\n", err)
		return
	}

	host := req.Host
	hostname := host
	if h, _, err2 := net.SplitHostPort(host); err2 == nil {
		hostname = h
	}

	if hostname == "" || hostname == "localhost" || hostname == "127.0.0.1" {
		hostname = "cloudcode-pa.googleapis.com"
		host = hostname
		logger.Printf("[HTTP] ⚠️  Local/No Host header from %s. Using fallback: %s\n", src.RemoteAddr(), hostname)
	}

	dialAddr := host
	if !strings.Contains(dialAddr, ":") {
		dialAddr = dialAddr + ":80"
	}

	// Dynamic override case: use resolved IP if available
	if realIP, ok := l.ResolvedIPs[hostname]; ok {
		dialAddr = net.JoinHostPort(realIP, "80")
	}

	// Trigger OnConnect for JS hooks (proxy/WG routing)
	localAddr := src.LocalAddr().String()
	localHost, _, _ := net.SplitHostPort(localAddr)
	connInfo := &engine.ConnInfo{
		Type:    "http",
		Source:  src.RemoteAddr().String(),
		Dest:    hostname,
		IP:      src.RemoteAddr().String(),
		Through: engine.GetIPType(localHost),
		Path:    req.URL.Path,
	}
	tunnel := l.engine.OnConnect(connInfo)
	if tunnel != nil && strings.ToLower(tunnel.Type) == "drop" {
		logger.Printf("[HTTP] 🚫 Connection dropped by OnConnect for %s\n", src.RemoteAddr())
		return
	}

	logger.Printf("[HTTP] 🔗 Proxying %s -> %s (%s)\n", src.RemoteAddr(), dialAddr, hostname)

	var dst net.Conn
	if tunnel != nil {
		dialer := &proxy.UniversalDialer{Tunnel: tunnel}
		dst, err = dialer.Dial("tcp", dialAddr)
	} else {
		dst, err = net.Dial("tcp", dialAddr)
	}
	if err != nil {
		logger.Printf("[HTTP] ❌ Failed to connect to target %s: %v\n", dialAddr, err)
		return
	}
	defer dst.Close()

	// Write the initial request to target
	if err := req.Write(dst); err != nil {
		return
	}

	// Start bi-directional relay using the regular Relay module
	// to ensure all packets are ingested and handled by JS API
	relay := proxy.NewRelay(l.engine, hostname, false)
	relay.RegisterConn(connInfo)

	// Since we already read the request headers with bufio.Reader,
	// we need to wrap the source connection to include the buffered data
	// if we were to continue reading from it.
	// However, HandleConn in http_listener already consumed the request.
	// For transparent HTTP, it's simpler to just relay the rest.

	// But wait, the relay needs to see the request too if it's to be logged.
	// SOCKS5/Proxy listeners handle this by passing the whole conn to Relay
	// after the initial handshake.

	// Create a combined reader for the relay to see the buffered data
	multisrc := &proxy.BufferedConn{Conn: src, Reader: reader}
	relay.Start(multisrc, dst)
}
