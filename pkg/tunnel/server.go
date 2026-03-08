package tunnel

import (
	"bufio"
	ctls "crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/protocol/tls"
)

// StreamIDPing is a reserved stream ID for PING/PONG keep-alive.
const StreamIDPing = uint32(0)

type NKTunnelServer struct {
	addr        string
	authFunc    func(user, pass string) bool
	portManager *PortManager
	sessions    map[string]*TunnelSession
	mu          sync.RWMutex
	engine      engine.Engine
	ca          *tls.CA
	publicIPv4  string // Cached public IPv4
	publicIPv6  string // Cached public IPv6
}

type TunnelSession struct {
	User           string
	ControlConn    net.Conn
	AssignedStart  int
	AssignedEnd    int
	Protocol       string
	Streams        map[uint32]*Stream
	recentlyClosed map[uint32]bool // Track recently-closed streams to avoid 'unknown' logs
	streamMu       sync.RWMutex
	writeMu        sync.Mutex // protects concurrent writes to ControlConn
	nextStreamID   uint32     // Mutex-protected counter for unique stream IDs
}

type Stream struct {
	ID   uint32
	Conn net.Conn
}

type PortManager struct {
	mu    sync.Mutex
	used  map[int]bool
	start int
	end   int
}

func NewPortManager(start, end int) *PortManager {
	return &PortManager{
		used:  make(map[int]bool),
		start: start,
		end:   end,
	}
}

func (pm *PortManager) AllocateRange(start, end int) (int, int, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	size := end - start + 1
	if size <= 0 {
		size = 1
		end = start
	}

	// Try requested range
	if start != 0 {
		canAllocate := true
		for p := start; p <= end; p++ {
			if p < pm.start || p > pm.end || pm.used[p] {
				canAllocate = false
				break
			}
		}
		if canAllocate {
			for p := start; p <= end; p++ {
				pm.used[p] = true
			}
			return start, end, nil
		}
	}

	// Find any available range of same size
	for s := pm.start; s <= pm.end-size+1; s++ {
		canAllocate := true
		for p := s; p < s+size; p++ {
			if pm.used[p] {
				canAllocate = false
				break
			}
		}
		if canAllocate {
			for p := s; p < s+size; p++ {
				pm.used[p] = true
			}
			return s, s + size - 1, nil
		}
	}

	return 0, 0, fmt.Errorf("no ports available for requested size")
}

func (pm *PortManager) ReleaseRange(start, end int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for p := start; p <= end; p++ {
		delete(pm.used, p)
	}
}

func (pm *PortManager) Release(port int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.used, port)
}

func NewNKTunnelServer(addr string, auth func(user, pass string) bool, engine engine.Engine, ca *tls.CA, portRange string) *NKTunnelServer {
	start, end := 10000, 20000
	if portRange != "" {
		fmt.Sscanf(portRange, "%d-%d", &start, &end)
		if end == 0 {
			end = start
		}
	}
	return &NKTunnelServer{
		addr:        addr,
		authFunc:    auth,
		portManager: NewPortManager(start, end),
		sessions:    make(map[string]*TunnelSession),
		engine:      engine,
		ca:          ca,
	}
}

func (s *NKTunnelServer) Start() error {
	// Detect our public IPs in background to avoid blocking startup (especially in tests or offline)
	go func() {
		s.publicIPv4, s.publicIPv6 = detectPublicIPs()
		if s.publicIPv4 != "" {
			fmt.Printf("[NK-Tunnel] Server public IPv4: %s\n", s.publicIPv4)
		}
		if s.publicIPv6 != "" {
			fmt.Printf("[NK-Tunnel] Server public IPv6: %s\n", s.publicIPv6)
		}
	}()

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	fmt.Printf("[NK-Tunnel] Server listening on %s\n", s.addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go s.handleControl(conn)
	}
}

// GetPublicIPs returns the server's detected public IPs.
func (s *NKTunnelServer) GetPublicIPs() (string, string) {
	return s.publicIPv4, s.publicIPv6
}

func (s *NKTunnelServer) handleControl(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// 1. Auth Phase
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(line)
	if len(fields) < 3 || fields[0] != CmdAuth {
		s.sendErr(conn, ErrInvalidCmd)
		return
	}

	user, pass := fields[1], fields[2]
	if !s.authFunc(user, pass) {
		s.sendErr(conn, ErrAuthFailed)
		return
	}
	conn.Write([]byte(CmdOk + "\n"))

	// 2. Negotiation Phase
	line, err = reader.ReadString('\n')
	if err != nil {
		return
	}
	fields = strings.Fields(line)
	if len(fields) < 3 || fields[0] != CmdReq {
		s.sendErr(conn, ErrInvalidCmd)
		return
	}

	proto := fields[1]
	reqRange := fields[2]
	reqStart, reqEnd := 0, 0
	if strings.Contains(reqRange, "-") {
		fmt.Sscanf(reqRange, "%d-%d", &reqStart, &reqEnd)
	} else {
		fmt.Sscanf(reqRange, "%d", &reqStart)
		reqEnd = reqStart
	}

	assignedStart, assignedEnd, err := s.portManager.AllocateRange(reqStart, reqEnd)
	if err != nil {
		s.sendErr(conn, ErrPortFull)
		return
	}
	defer s.portManager.ReleaseRange(assignedStart, assignedEnd)

	// Send response with assigned ports AND public IPs (concatenated or primary)
	publicIP := s.publicIPv4
	if publicIP == "" {
		publicIP = s.publicIPv6
	}
	conn.Write([]byte(fmt.Sprintf("%s %d %d %s\n", CmdRes, assignedStart, assignedEnd, publicIP)))

	// 3. Keep-alive and Port Listening
	session := &TunnelSession{
		User:           user,
		ControlConn:    conn,
		AssignedStart:  assignedStart,
		AssignedEnd:    assignedEnd,
		Protocol:       proto,
		Streams:        make(map[uint32]*Stream),
		recentlyClosed: make(map[uint32]bool),
	}

	s.mu.Lock()
	s.sessions[fmt.Sprintf("%s:%d", user, assignedStart)] = session
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.sessions, fmt.Sprintf("%s:%d", user, assignedStart))
		s.mu.Unlock()
	}()

	// Start listener for public traffic
	stopCh := make(chan struct{})
	go s.listenPublicRange(session, stopCh)
	defer close(stopCh)

	// Run frame loop for data multiplexing
	s.runFrameLoop(session)
}

func (s *NKTunnelServer) listenPublicRange(sess *TunnelSession, stop chan struct{}) {
	for port := sess.AssignedStart; port <= sess.AssignedEnd; port++ {
		go s.listenSinglePublic(sess, port, stop)
	}
}

func (s *NKTunnelServer) listenSinglePublic(sess *TunnelSession, port int, stop chan struct{}) {
	addr := fmt.Sprintf(":%d", port)

	var ln net.Listener
	var err error

	if sess.Protocol == ProtoHTTPS {
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			go s.serveHTTPSWithRedirect(sess, ln, port, stop)
			return
		}
	} else if sess.Protocol == ProtoUDP {
		// UDP is handled separately
		go s.listenPublicUDP(sess, port, stop)
		return
	} else {
		ln, err = net.Listen("tcp", addr)
	}

	if err != nil {
		fmt.Printf("[NK-Tunnel] Failed to listen on %s: %v\n", addr, err)
		return
	}
	fmt.Printf("[NK-Tunnel] Listening for public traffic on %s (Protocol: %s)\n", addr, sess.Protocol)
	defer ln.Close()

	go func() {
		<-stop
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-stop:
				return
			default:
				continue
			}
		}
		go s.handlePublicConn(sess, conn, port)
	}
}

// Frame header: [4 bytes StreamID][4 bytes PayloadLength]
type Frame struct {
	StreamID uint32
	Payload  []byte
}

func (s *NKTunnelServer) readFrame(conn net.Conn) (*Frame, error) {
	header := make([]byte, 8)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	streamID := binary.BigEndian.Uint32(header[:4])
	length := binary.BigEndian.Uint32(header[4:8])

	// Release header immediately — we don't need it anymore
	header = nil

	if length > 1024*1024 { // 1MB limit per frame
		return nil, fmt.Errorf("frame too large: %d bytes", length)
	}

	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, err
		}
	}
	return &Frame{StreamID: streamID, Payload: payload}, nil
}

func (s *NKTunnelServer) writeFrame(conn net.Conn, streamID uint32, payload []byte) error {
	length := uint32(len(payload))
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[:4], streamID)
	binary.BigEndian.PutUint32(header[4:8], length)

	conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	// Release header immediately
	header = nil

	if length > 0 {
		conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		_, err := conn.Write(payload)
		return err
	}
	return nil
}

func (s *NKTunnelServer) handlePublicConn(sess *TunnelSession, conn net.Conn, port int) {
	defer conn.Close()

	sess.streamMu.Lock()
	sess.nextStreamID++
	streamID := sess.nextStreamID
	stream := &Stream{ID: streamID, Conn: conn}
	sess.Streams[streamID] = stream
	sess.streamMu.Unlock()
	defer func() {
		sess.streamMu.Lock()
		delete(sess.Streams, streamID)
		sess.recentlyClosed[streamID] = true // Track as recently closed to avoid 'unknown stream' errors
		sess.streamMu.Unlock()
	}()

	fmt.Printf("[NK-Tunnel] New connection on port %d assigned to %s, streamID: %d\n", port, sess.User, streamID)

	// Notify client about new connection and the specific port
	sess.writeMu.Lock()
	err := s.writeFrame(sess.ControlConn, streamID, []byte(fmt.Sprintf("OPEN:%d", port)))
	sess.writeMu.Unlock()
	if err != nil {
		fmt.Printf("[NK-Tunnel] Error sending OPEN frame for stream %d: %v\n", streamID, err)
		return
	}

	// Relay data from public connection to control connection
	buf := make([]byte, 32*1024)
	defer func() { buf = nil }() // Release buffer to GC
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sess.writeMu.Lock()
			writeErr := s.writeFrame(sess.ControlConn, streamID, buf[:n])
			sess.writeMu.Unlock()
			if writeErr != nil {
				fmt.Printf("[NK-Tunnel] Error writing frame for stream %d: %v\n", streamID, writeErr)
				break
			}
		}
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "closed network connection") {
				fmt.Printf("[NK-Tunnel] Error reading from public conn for stream %d: %v\n", streamID, err)
			}
			break
		}
	}
	// Send EOF frame — protected by write mutex
	sess.writeMu.Lock()
	s.writeFrame(sess.ControlConn, streamID, nil)
	sess.writeMu.Unlock()
	fmt.Printf("[NK-Tunnel] Stream %d closed (public conn EOF)\n", streamID)
}

// In handleControl, after negotiation, start the frame processing loop
func (s *NKTunnelServer) runFrameLoop(sess *TunnelSession) {
	for {
		frame, err := s.readFrame(sess.ControlConn)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("[NK-Tunnel] Error reading frame from control conn for user %s: %v\n", sess.User, err)
			}
			break
		}

		// Handle PING/PONG keep-alive (StreamID 0 is reserved)
		if frame.StreamID == StreamIDPing {
			payload := string(frame.Payload)
			if payload == "PING" {
				sess.writeMu.Lock()
				s.writeFrame(sess.ControlConn, StreamIDPing, []byte("PONG"))
				sess.writeMu.Unlock()
			}
			continue
		}

		sess.streamMu.RLock()
		stream, ok := sess.Streams[frame.StreamID]
		sess.streamMu.RUnlock()

		if ok {
			if len(frame.Payload) == 0 { // EOF or close signal
				fmt.Printf("[NK-Tunnel] Received EOF for stream %d from client\n", frame.StreamID)
				stream.Conn.Close()
			} else {
				_, err := stream.Conn.Write(frame.Payload)
				if err != nil {
					fmt.Printf("[NK-Tunnel] Error writing to public conn for stream %d: %v\n", frame.StreamID, err)
					stream.Conn.Close() // Close stream on write error
				}
			}
		} else {
			// Check if this was a recently-closed stream (normal race) vs truly unknown
			sess.streamMu.RLock()
			wasRecentlyClosed := sess.recentlyClosed[frame.StreamID]
			sess.streamMu.RUnlock()
			if !wasRecentlyClosed {
				fmt.Printf("[NK-Tunnel] Received frame for unknown stream ID %d from client\n", frame.StreamID)
			}
			// Silently ignore frames for recently-closed streams (expected EOF race)
		}
	}
	fmt.Printf("[NK-Tunnel] Control connection for user %s closed, cleaning up streams.\n", sess.User)
	// Clean up all streams associated with this session if the control connection closes
	sess.streamMu.Lock()
	for _, stream := range sess.Streams {
		stream.Conn.Close()
	}
	sess.Streams = make(map[uint32]*Stream) // Clear the map
	sess.streamMu.Unlock()
}

func (s *NKTunnelServer) listenPublicUDP(sess *TunnelSession, port int, stop chan struct{}) {
	addr := fmt.Sprintf(":%d", port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Printf("[NK-Tunnel] Failed to listen UDP on %s: %v\n", addr, err)
		return
	}
	defer conn.Close()

	go func() {
		<-stop
		conn.Close()
	}()

	buf := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}

		// For UDP, we use the port as part of the StreamID or dynamic allocation
		// To simplify, we'll embed the port in the streamID or header.
		// For now, using port as part of ID.
		streamID := uint32(port)
		sess.writeMu.Lock()
		s.writeFrame(sess.ControlConn, streamID, buf[:n])
		sess.writeMu.Unlock()
	}
}

func (s *NKTunnelServer) serveHTTPSWithRedirect(sess *TunnelSession, ln net.Listener, port int, stop chan struct{}) {
	defer ln.Close()

	tlsConfig := &ctls.Config{
		GetCertificate: func(hello *ctls.ClientHelloInfo) (*ctls.Certificate, error) {
			hostname := hello.ServerName
			if hostname == "" {
				hostname = "localhost"
			}
			certs, err := s.ca.GenerateCert(hostname)
			if err != nil {
				return nil, err
			}
			return &certs[0], nil
		},
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-stop:
				return
			default:
				continue
			}
		}

		go func(c net.Conn) {
			// Peek initial bytes to detect TLS vs HTTP
			peekBuf := make([]byte, 4096)
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := c.Read(peekBuf)
			c.SetReadDeadline(time.Time{})

			if err == nil && n > 0 {
				if peekBuf[0] == 22 {
					// TLS Handshake — wrap and handle
					tlsConn := ctls.Server(&PeekedConn{Conn: c, Data: peekBuf[:n], Off: 0}, tlsConfig)
					s.handlePublicConn(sess, tlsConn, port)
				} else {
					// HTTP plaintext — extract Host header for proper redirect
					host := extractHostFromHTTP(peekBuf[:n], port)
					resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", host)
					c.Write([]byte(resp))
					c.Close()
				}
			} else {
				c.Close()
			}
		}(conn)
	}
}

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

func (s *NKTunnelServer) sendErr(conn net.Conn, code string) {
	conn.Write([]byte(fmt.Sprintf("%s %s\n", CmdErr, code)))
}

// extractHostFromHTTP parses the Host header from raw HTTP request bytes.
// Falls back to the server's public IP with port if Host is not found.
func extractHostFromHTTP(data []byte, port int) string {
	lines := strings.Split(string(data), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host := strings.TrimSpace(line[5:])
			if host != "" {
				// If the original request has a non-standard port, preserve it
				// Otherwise, just return the host for the HTTPS redirect
				if !strings.Contains(host, ":") && port != 80 && port != 443 {
					return fmt.Sprintf("%s:%d", host, port)
				}
				return host
			}
		}
	}
	// Fallback: no Host header found
	return fmt.Sprintf("localhost:%d", port)
}

// VerifyPort checks if a port is accessible from outside.
func (s *NKTunnelServer) VerifyPort(port int) bool {
	ips := []string{s.publicIPv4, s.publicIPv6}
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// detectPublicIPs determines the public IPv4 and IPv6 of this server.
func detectPublicIPs() (string, string) {
	ipv4, ipv6 := "", ""

	services := []struct {
		url    string
		isIPv6 bool
	}{
		{"https://api.ipify.org", false},
		{"https://api64.ipify.org", true},
		{"https://ifconfig.me/ip", false},
		{"https://icanhazip.com", false},
		{"https://6.icanhazip.com", true},
	}

	client := &http.Client{Timeout: 5 * time.Second}
	for _, svc := range services {
		if (svc.isIPv6 && ipv6 != "") || (!svc.isIPv6 && ipv4 != "") {
			continue
		}

		resp, err := client.Get(svc.url)
		if err != nil {
			continue
		}
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		ipStr := strings.TrimSpace(string(body))
		ip := net.ParseIP(ipStr)
		if ip != nil {
			if ip.To4() != nil {
				ipv4 = ipStr
			} else {
				ipv6 = ipStr
			}
		}
	}

	// Fallback to local interfaces
	if ipv4 == "" || ipv6 == "" {
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok {
					ip := ipNet.IP
					if ip.IsGlobalUnicast() {
						if ip.To4() != nil && ipv4 == "" {
							ipv4 = ip.String()
						} else if ip.To4() == nil && ipv6 == "" {
							ipv6 = ip.String()
						}
					}
				}
			}
		}
	}

	return ipv4, ipv6
}
