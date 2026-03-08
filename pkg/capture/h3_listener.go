package capture

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	ltls "github.com/bacot120211/netkit-go/pkg/protocol/tls"
	"github.com/quic-go/quic-go/http3"
)

// H3Listener is an HTTP/3 MITM proxy listener using QUIC.
type H3Listener struct {
	addr      string
	engine    engine.Engine
	ca        *ltls.CA
	transport *http3.Transport
}

func NewH3Listener(addr string, ca *ltls.CA, e engine.Engine) *H3Listener {
	return &H3Listener{
		addr:   addr,
		engine: e,
		ca:     ca,
		transport: &http3.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Typical for MITM tools
			},
		},
	}
}

func (l *H3Listener) Start(ctx context.Context) error {
	server := &http3.Server{
		Addr:    l.addr,
		Handler: l,
		TLSConfig: &tls.Config{
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				// Use the same MITM certificate generation logic
				certs, err := l.ca.GenerateCert(hello.ServerName)
				if err != nil {
					return nil, err
				}
				return &tls.Config{
					Certificates: certs,
					NextProtos:   []string{"h3"},
				}, nil
			},
		},
	}

	logger.Infof("[H3] 🚀 HTTP/3 Listener active on %s (UDP)\n", l.addr)

	go func() {
		<-ctx.Done()
		_ = server.Close()
		_ = l.transport.Close()
	}()

	return server.ListenAndServe()
}

func (l *H3Listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	localHost, _, _ := net.SplitHostPort(l.addr)
	srcHost, srcPortStr, _ := net.SplitHostPort(r.RemoteAddr)
	dstHost, dstPortStr, _ := net.SplitHostPort(r.Host)
	if dstPortStr == "" {
		dstPortStr = "443" // Default for H3
	}

	srcPort := uint16(0)
	dstPort := uint16(443)
	fmt.Sscanf(srcPortStr, "%d", &srcPort)
	fmt.Sscanf(dstPortStr, "%d", &dstPort)

	connInfo := &engine.ConnInfo{
		Type:    "h3",
		Source:  r.RemoteAddr,
		Dest:    r.Host,
		IP:      srcHost,
		Through: engine.GetIPType(localHost),
	}

	// Reconstruct the full URL since r.URL might be relative
	if r.URL.Scheme == "" {
		r.URL.Scheme = "https"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	logger.Printf("[H3] 📨 Intercepting %s %s from %s\n", r.Method, r.URL.String(), r.RemoteAddr)

	// Clone the request for proxying
	proxyReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		logger.Errorf("[H3] ❌ Failed to create proxy request: %v\n", err)
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for k, vv := range r.Header {
		for _, v := range vv {
			proxyReq.Header.Add(k, v)
		}
	}

	// Execute the request via H3 RoundTripper
	resp, err := l.transport.RoundTrip(proxyReq)
	if err != nil {
		logger.Errorf("[H3] ❌ RoundTrip error for %s: %v\n", r.URL.String(), err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Copy response body and log it to engine
	bodyBytes, _ := io.ReadAll(resp.Body)
	_, _ = w.Write(bodyBytes)

	// Prepare detailed metadata
	metadata := make(map[string]interface{})
	metadata["http_method"] = r.Method
	metadata["http_url"] = r.URL.String()
	metadata["http_version"] = r.Proto
	metadata["http_status"] = resp.StatusCode
	metadata["request_headers"] = r.Header
	metadata["response_headers"] = resp.Header

	// Log to engine with full metadata
	p := &engine.Packet{
		Timestamp:  time.Now().UnixNano(),
		Source:     srcHost,
		SourcePort: srcPort,
		Dest:       dstHost,
		DestPort:   dstPort,
		Protocol:   "quic/h3",
		Payload:    bodyBytes,
		Metadata:   metadata,
		Conn:       connInfo,
	}
	l.engine.Process(p, nil)

	logger.Infof("[H3] ✅ Successfully intercepted and proxied request for %s\n", r.Host)
}
