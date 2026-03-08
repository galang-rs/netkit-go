package proxy

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
)

// Relay handles bi-directional data transfer between two connections
type Relay struct {
	engine     engine.Engine
	Hostname   string
	Decrypted  bool
	Conn       *engine.ConnInfo
	TargetHost string
	TargetPort uint16
	TargetIP   string
}

func (r *Relay) RegisterConn(info *engine.ConnInfo) {
	r.Conn = info
}

func NewRelay(e engine.Engine, hostname string, decrypted bool) *Relay {
	h, p, err := net.SplitHostPort(hostname)
	if err != nil {
		h = hostname
		p = "0"
	}
	var port uint16
	if v, err := strconv.ParseUint(p, 10, 16); err == nil {
		port = uint16(v)
	}

	// Resolve IP for security checks
	targetIP := h
	if net.ParseIP(h) == nil {
		if ips, err := net.LookupIP(h); err == nil && len(ips) > 0 {
			targetIP = ips[0].String()
		}
	}

	return &Relay{
		engine:     e,
		Hostname:   hostname,
		Decrypted:  decrypted,
		TargetHost: h,
		TargetPort: port,
		TargetIP:   targetIP,
	}
}

func (r *Relay) Start(src, dst net.Conn) {
	logger.Printf("[Relay] New relay: %s <-> %s\n", src.RemoteAddr(), dst.RemoteAddr())

	// Enable Keep-Alive to prevent automatic disconnection
	if tcpSrc, ok := src.(*net.TCPConn); ok {
		_ = tcpSrc.SetKeepAlive(true)
		_ = tcpSrc.SetKeepAlivePeriod(30 * time.Second)
	}
	if tcpDst, ok := dst.(*net.TCPConn); ok {
		_ = tcpDst.SetKeepAlive(true)
		_ = tcpDst.SetKeepAlivePeriod(30 * time.Second)
	}

	// Channel to signal completion
	done := make(chan struct{}, 2)

	go r.forward(src, dst, "REQUEST", done)
	go r.forward(dst, src, "RESPONSE", done)

	// Wait for both directions to finish
	for i := 0; i < 2; i++ {
		<-done
	}
	logger.Printf("[Relay] Session ended: %s <-> %s\n", src.RemoteAddr(), dst.RemoteAddr())
}

func (r *Relay) forward(src, dst net.Conn, direction string, done chan struct{}) {
	defer func() { done <- struct{}{} }()

	buf := make([]byte, 32*1024) // Allocate fresh buffer per connection
	defer func() { buf = nil }() // Aggressively release to GC on exit

	for {
		n, err := src.Read(buf)
		if n > 0 {
			// Extract ports for metadata — use strconv instead of fmt.Sscanf
			srcAddr := src.RemoteAddr().String()
			dstAddr := dst.RemoteAddr().String()

			srcHost, srcPortStr, _ := net.SplitHostPort(srcAddr)
			var srcPort uint16
			if v, parseErr := strconv.ParseUint(srcPortStr, 10, 16); parseErr == nil {
				srcPort = uint16(v)
			}

			// Use atomic ID instead of time-based (avoids collisions)
			p := &engine.Packet{
				ID:         engine.NextPacketID(),
				Timestamp:  time.Now().Unix(),
				Source:     srcHost,
				SourcePort: srcPort,
				Dest:       r.TargetIP,
				DestPort:   r.TargetPort,
				Protocol:   "TCP",
				Payload:    append([]byte(nil), buf[:n]...),
				Metadata: map[string]interface{}{
					"Direction": direction,
					"Decrypted": r.Decrypted,
					"Hostname":  r.Hostname,
				},
				Conn: r.Conn,
			}

			// Process through engine (sniffing/injection)
			handledByCallback := false
			action := r.engine.Process(p, func(b []byte) error {
				handledByCallback = true
				_, writeErr := src.Write(b) // Responder writes back to source (client)
				return writeErr
			})

			// Save payload reference before releasing packet
			// (ReleasePacket nils p.Payload, so we must save it for write paths)
			processedPayload := p.Payload

			// Aggressively release packet after processing
			engine.ReleasePacket(p)

			if action == engine.ActionDrop {
				continue // Don't terminate relay on drop, just skip this packet
			}

			if action == engine.ActionBypass {
				logger.Printf("[Relay] ⚡ Bypass active for %s (%s -> %s)\n", direction, srcAddr, dstAddr)
				// Write current payload first
				if _, writeErr := dst.Write(processedPayload); writeErr != nil {
					return
				}
				// Use io.Copy for the rest of the stream
				_, _ = io.Copy(dst, src)
				return
			}

			// If action is ActionContinue and NOT handled by callback, write original/modified payload
			if !handledByCallback {
				if _, writeErr := dst.Write(processedPayload); writeErr != nil {
					return
				}
			}
		}
		if err != nil {
			// EOF is expected when connection closes
			return
		}
	}
}

// BufferedConn wraps a net.Conn and an io.Reader (like bufio.Reader)
// to allow reading back data already peeked/buffered.
type BufferedConn struct {
	net.Conn
	Reader io.Reader
}

func (c *BufferedConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

func GetLocalIPForRelay() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

// formatAddr creates host:port safely
func formatAddr(host string, port uint16) string {
	return fmt.Sprintf("%s:%d", host, port)
}
