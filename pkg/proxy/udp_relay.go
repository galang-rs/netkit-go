package proxy

import (
	"net"
	"sync"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
)

// UDPPeer represents a side of the UDP conversation
type UDPPeer struct {
	Addr *net.UDPAddr
	Conn *net.UDPConn
}

// UDPRelay handles bi-directional UDP traffic
type UDPRelay struct {
	engine   engine.Engine
	mu       sync.Mutex // Use Mutex instead of RWMutex to prevent TOCTOU races
	sessions map[string]*udpSession
	Conn     *engine.ConnInfo
}

func (r *UDPRelay) RegisterConn(conn *engine.ConnInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Conn = conn
}

type udpSession struct {
	mu         sync.Mutex
	clientAddr *net.UDPAddr
	remoteConn *net.UDPConn
	lastActive time.Time
	done       chan struct{}
}

func NewUDPRelay(e engine.Engine) *UDPRelay {
	return &UDPRelay{
		engine:   e,
		sessions: make(map[string]*udpSession),
	}
}

// Start listens on the local address and relays to the target address
func (r *UDPRelay) Start(listenAddrStr, targetAddrStr string) error {
	laddr, err := net.ResolveUDPAddr("udp", listenAddrStr)
	if err != nil {
		return err
	}

	raddr, err := net.ResolveUDPAddr("udp", targetAddrStr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	logger.Printf("[UDPRelay] Listening on %s -> %s\n", listenAddrStr, targetAddrStr)

	buf := make([]byte, 64*1024)
	for {
		n, srcAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			logger.Printf("[UDPRelay] Read error: %v\n", err)
			continue
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		go r.handlePacket(conn, srcAddr, raddr, payload)
	}
}

func (r *UDPRelay) handlePacket(listenConn *net.UDPConn, srcAddr, dstAddr *net.UDPAddr, payload []byte) {
	sessionID := srcAddr.String()

	// FIX: Use single Lock to prevent TOCTOU race condition.
	// Previously used RLock-check-RUnlock-Lock pattern which allowed two goroutines
	// to both see "not exists" and create duplicate sessions.
	r.mu.Lock()
	session, ok := r.sessions[sessionID]
	if !ok {
		// Create new session under the same lock — no race possible
		targetConn, err := net.DialUDP("udp", nil, dstAddr)
		if err != nil {
			r.mu.Unlock()
			logger.Printf("[UDPRelay] Failed to dial target %s: %v\n", dstAddr, err)
			return
		}

		session = &udpSession{
			clientAddr: srcAddr,
			remoteConn: targetConn,
			lastActive: time.Now(),
			done:       make(chan struct{}),
		}

		r.sessions[sessionID] = session
		r.mu.Unlock()

		// Start background listener for responses from target
		go r.relayResponse(listenConn, session)
		// Start janitor for this session
		go r.sessionJanitor(sessionID)
	} else {
		r.mu.Unlock()
	}

	session.mu_update_activity()

	// Ingest into engine
	p := &engine.Packet{
		ID:         engine.NextPacketID(),
		Timestamp:  time.Now().Unix(),
		Source:     srcAddr.IP.String(),
		SourcePort: uint16(srcAddr.Port),
		Dest:       dstAddr.IP.String(),
		DestPort:   uint16(dstAddr.Port),
		Protocol:   "UDP",
		Payload:    payload,
		Metadata: map[string]interface{}{
			"Direction": "REQUEST",
		},
		Conn: r.Conn,
	}

	action := r.engine.Process(p, nil)

	// Save payload before cleanup
	processedPayload := p.Payload
	engine.ReleasePacket(p)

	if action == engine.ActionDrop {
		return
	}

	_, err := session.remoteConn.Write(processedPayload)
	if err != nil {
		logger.Printf("[UDPRelay] Write to target error: %v\n", err)
	}
}

func (r *UDPRelay) relayResponse(listenConn *net.UDPConn, session *udpSession) {
	buf := make([]byte, 64*1024)
	defer func() { buf = nil }() // Release buffer to GC

	for {
		n, _, err := session.remoteConn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		session.mu_update_activity()

		payload := make([]byte, n)
		copy(payload, buf[:n])

		// Ingest into engine
		p := &engine.Packet{
			ID:         engine.NextPacketID(),
			Timestamp:  time.Now().Unix(),
			Source:     session.remoteConn.RemoteAddr().(*net.UDPAddr).IP.String(),
			SourcePort: uint16(session.remoteConn.RemoteAddr().(*net.UDPAddr).Port),
			Dest:       session.clientAddr.IP.String(),
			DestPort:   uint16(session.clientAddr.Port),
			Protocol:   "UDP",
			Payload:    payload,
			Metadata: map[string]interface{}{
				"Direction": "RESPONSE",
			},
			Conn: r.Conn,
		}

		action := r.engine.Process(p, nil)

		// Save payload before cleanup
		processedPayload := p.Payload
		engine.ReleasePacket(p)

		if action == engine.ActionDrop {
			continue
		}

		_, err = listenConn.WriteToUDP(processedPayload, session.clientAddr)
		if err != nil {
			logger.Printf("[UDPRelay] Write to client error: %v\n", err)
		}
	}
}

func (s *udpSession) mu_update_activity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActive = time.Now()
}

func (r *UDPRelay) sessionJanitor(sessionID string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		r.mu.Lock()
		session, ok := r.sessions[sessionID]
		if !ok {
			r.mu.Unlock()
			return
		}

		session.mu.Lock()
		active := session.lastActive
		session.mu.Unlock()

		if time.Since(active) > 60*time.Second {
			delete(r.sessions, sessionID)
			r.mu.Unlock()
			session.remoteConn.Close()
			return
		}
		r.mu.Unlock()
	}
}
