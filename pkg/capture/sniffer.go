package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/proc"
	"github.com/bacot120211/netkit-go/pkg/proxy"
)

// connKey uniquely identifies a connection by its local and remote port pair
type connKey struct {
	localPort  uint16
	remotePort uint16
}

// pendingPacket holds a packet whose remote IP was not yet known at capture time.
// It will be flushed retroactively once the real remote IP is learned.
type pendingPacket struct {
	buf       []byte
	count     uint64
	proto     byte
	srcIP     string // may be "?"
	dstIP     string // may be "?"
	srcPort   uint16
	dstPort   uint16
	headerLen int
}

// Sniffer implements transparent capture using Raw Sockets on Windows
type Sniffer struct {
	engine      engine.Engine
	ips         []string
	localIPs    map[string]struct{}
	targetPorts []uint16
	SniffAll    bool
	RawSniff    bool
	Verbose     bool
	mu          sync.RWMutex
	bufPool     sync.Pool

	targetIPs     map[string]string // IP -> Domain name for bypass detection
	domainCache   map[string]string // IP -> Domain name (learned via DNS/SNI)
	lastWarning   time.Time
	lastWarningMu sync.Mutex // protects lastWarning from concurrent access

	// Connection tracking: learn real remote IPs from packets with full headers,
	// then use them to resolve headerless outgoing packets.
	connMu  sync.RWMutex
	connMap map[connKey]string // {localPort, remotePort} -> remoteIP

	// Retroactive tracking: buffer packets with unknown remote IP;
	// flush them once the real IP is learned via a full-header packet.
	pendingMu  sync.Mutex
	pendingMap map[connKey][]pendingPacket // {localPort, remotePort} -> buffered packets

	// PID tracking
	pidMu         sync.RWMutex
	tcpPortPidMap map[uint16]uint32
	udpPortPidMap map[uint16]uint32

	// Parallel ingestion
	ingestChan chan *rawPacket

	// Happy Eyeballs
	dialer *proxy.HappyDialer

	// First-seen port tracker for ambiguous loopback traffic
	portTrackerMu sync.Mutex
	portTracker   map[uint16]uint16 // {lowPort, highPort} -> port that sent FIRST (the client)
}

type rawPacket struct {
	buf        []byte
	count      uint64
	listenIP   string
	remoteAddr string
	isIPv6     bool
}

func NewSniffer(ips []string, e engine.Engine) *Sniffer {
	s := &Sniffer{
		ips:           ips,
		engine:        e,
		targetPorts:   make([]uint16, 0),
		connMap:       make(map[connKey]string),
		pendingMap:    make(map[connKey][]pendingPacket),
		targetIPs:     make(map[string]string),
		domainCache:   make(map[string]string),
		tcpPortPidMap: make(map[uint16]uint32),
		udpPortPidMap: make(map[uint16]uint32),
		ingestChan:    make(chan *rawPacket, 10000), // Large buffer to absorb bursts
		dialer:        proxy.NewHappyDialer(),
		bufPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 65536)
			},
		},
	}
	s.SetLocalIPs(ips)
	s.portTracker = make(map[uint16]uint16)
	return s
}

func (s *Sniffer) SetBypassDetection(ipToDomain map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targetIPs = ipToDomain
}

func (s *Sniffer) AddDomainMapping(ip, domain string) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	s.domainCache[ip] = domain
	if s.Verbose {
		logger.Printf("[Sniffer] [Cache] Added mapping: %s -> %s\n", ip, domain)
	}
}

func (s *Sniffer) UpdatePorts(ports []uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targetPorts = ports
	if s.Verbose {
		logger.Printf("[Sniffer] Updated target port list: %v\n", ports)
	}
}

func (s *Sniffer) ResetPorts() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targetPorts = make([]uint16, 0)
	if s.Verbose {
		logger.Printf("[Sniffer] Target ports reset. Waiting for new targets...\n")
	}
}

// trackConnection stores a mapping from local port pair to the real remote IP.
// Called when we see a packet with a full IP header (parseIPv4/parseIPv6).
// Also flushes any retroactively-pending packets for this port pair.
func (s *Sniffer) trackConnection(localPort, remotePort uint16, remoteIP string) {
	s.connMu.Lock()
	key := connKey{localPort, remotePort}
	isNew := false
	if old, exists := s.connMap[key]; !exists || old != remoteIP {
		s.connMap[key] = remoteIP
		isNew = true
		if s.Verbose {
			logger.Printf("[Sniffer] Tracked connection: localPort=%d <-> %s:%d\n", localPort, remoteIP, remotePort)
		}
		// Try to learn domain from remoteIP if possible (e.g. if we have it in cache)
		domain := s.domainCache[remoteIP]
		if domain != "" {
			logger.Printf("[Sniffer]   └─ Learned domain: %s\n", domain)
		}
	}
	s.connMu.Unlock()

	// Flush pending packets that were buffered while IP was unknown.
	if isNew {
		s.flushPending(key, localPort, remotePort, remoteIP)
	}
}

func (s *Sniffer) startPIDRefresher(ctx context.Context) {
	// Initial refresh
	s.refreshPIDs()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshPIDs()
		}
	}
}

func (s *Sniffer) refreshPIDs() {
	tcpConns, udpConns, err := proc.GetSystemConnections()
	if err == nil {
		s.pidMu.Lock()
		s.tcpPortPidMap = make(map[uint16]uint32)
		s.udpPortPidMap = make(map[uint16]uint32)

		var pidsToWarm []uint32

		for port, info := range tcpConns {
			s.tcpPortPidMap[port] = info.PID
			pidsToWarm = append(pidsToWarm, info.PID) // fixed: added info.PID

			// Proactively seed connMap if we have remote IP
			if info.RemoteIP != "" {
				s.connMu.Lock()
				s.connMap[connKey{localPort: port, remotePort: info.RemotePort}] = info.RemoteIP
				s.connMu.Unlock()
			}
		}
		for port, info := range udpConns {
			s.udpPortPidMap[port] = info.PID
			pidsToWarm = append(pidsToWarm, info.PID)
		}
		s.pidMu.Unlock()

		// Warm process names in background
		go proc.WarmProcessCache(pidsToWarm)

	} else if s.Verbose {
		logger.Printf("[Sniffer] [PID] Failed to refresh PID mappings: %v\n", err)
	}
}

func (s *Sniffer) getPID(port uint16, protocol byte) uint32 {
	s.pidMu.RLock()
	defer s.pidMu.RUnlock()
	if protocol == 6 { // TCP
		return s.tcpPortPidMap[port]
	} else if protocol == 17 { // UDP
		return s.udpPortPidMap[port]
	}
	return 0
}

// flushPending replaces "?" with the now-known remoteIP and ingests buffered packets.
func (s *Sniffer) flushPending(key connKey, localPort, remotePort uint16, remoteIP string) {
	s.pendingMu.Lock()
	pkts, ok := s.pendingMap[key]
	if ok {
		delete(s.pendingMap, key)
	}
	s.pendingMu.Unlock()

	if !ok || len(pkts) == 0 {
		return
	}

	if s.Verbose {
		logger.Printf("[Sniffer] [retroactive] Flushing %d buffered packet(s) for localPort=%d <-> %s:%d\n",
			len(pkts), localPort, remoteIP, remotePort)
	}

	for _, p := range pkts {
		srcIP := p.srcIP
		dstIP := p.dstIP
		if srcIP == "?" {
			srcIP = remoteIP
		}
		if dstIP == "?" {
			dstIP = remoteIP
		}
		protocol := "TCP"
		var protoNum byte = 6
		if p.proto == 17 {
			protocol = "UDP"
			protoNum = 17
		}

		pid := s.getPID(localPort, protoNum)
		processName := proc.GetProcessName(pid)

		ep := &engine.Packet{
			ID:          uint64(time.Now().UnixNano()),
			Timestamp:   time.Now().Unix(),
			Source:      srcIP,
			SourcePort:  p.srcPort,
			Dest:        dstIP,
			DestPort:    p.dstPort,
			Protocol:    protocol,
			Payload:     p.buf[p.headerLen:],
			PID:         pid,
			ProcessName: processName,
		}

		// Deduplication: Ignore packets matching our own proxy listeners to avoid quadruple logging
		if s.isLocalIP(ep.Source) || s.isLocalIP(ep.Dest) {
			s.mu.RLock()
			for _, targetPort := range s.targetPorts {
				if ep.SourcePort == targetPort || ep.DestPort == targetPort {
					s.mu.RUnlock()
					continue // Skip this packet, but continue with the loop for other packets
				}
			}
			s.mu.RUnlock()
		}

		s.engine.Ingest(ep)
	}
}

// bufferPending stores a packet that cannot be fully resolved yet.
// The buffer is capped at 1024 packets per key to prevent memory leaks while handling bursts.
func (s *Sniffer) bufferPending(key connKey, p pendingPacket) {
	const maxPending = 1024
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	list := s.pendingMap[key]
	if len(list) >= maxPending {
		// Drop oldest entry to stay within cap
		list = list[1:]
	}
	// Copy buf so the original read-buffer can be reused
	bufCopy := make([]byte, len(p.buf))
	copy(bufCopy, p.buf)
	p.buf = bufCopy
	s.pendingMap[key] = append(list, p)
}

// lookupConnection tries to find the real remote IP for a given port pair.
func (s *Sniffer) lookupConnection(localPort, remotePort uint16) string {
	s.connMu.RLock()
	defer s.connMu.RUnlock()
	return s.connMap[connKey{localPort, remotePort}]
}

// Start initializes the sniffer components.
func (s *Sniffer) SetLocalIPs(ips []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localIPs = make(map[string]struct{})
	for _, ip := range ips {
		s.localIPs[ip] = struct{}{}
	}
}

// isLocalIP checks if an IP belongs to one of the interfaces we are sniffing on.
func (s *Sniffer) isLocalIP(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.localIPs[ip]
	return ok
}

func (s *Sniffer) Start(ctx context.Context) error {
	if s.Verbose {
		logger.Printf("[Sniffer] Starting in %s mode...\n", map[bool]string{true: "RAW", false: "NORMAL"}[s.RawSniff])
	}
	proc.Verbose = s.Verbose
	go s.startPIDRefresher(ctx)

	// Launch workers for parallel ingestion
	const numWorkers = 8
	for i := 0; i < numWorkers; i++ {
		go s.worker(ctx)
	}

	var wg sync.WaitGroup
	for _, ip := range s.ips {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			if err := s.startCollector(ctx, targetIP); err != nil {
				logger.Printf("[Sniffer] Collector for %s failed: %v\n", targetIP, err)
			}
		}(ip)
	}
	wg.Wait()
	return nil
}

func (s *Sniffer) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-s.ingestChan:
			if p.isIPv6 {
				s.parseIPv6(p.buf, p.count, p.remoteAddr)
			} else {
				// HEURISTIC: Check if it's truly an IPv4 packet
				// Version=4 (byte 0 >> 4) and IHL >= 5 (byte 0 & 0x0F)
				isIPv4 := false
				if len(p.buf) >= 20 {
					version := p.buf[0] >> 4
					ihl := p.buf[0] & 0x0F
					if version == 4 && ihl >= 5 && int(ihl*4) <= len(p.buf) {
						// Double check Total Length if possible
						totalLen := binary.BigEndian.Uint16(p.buf[2:4])
						if int(totalLen) <= len(p.buf) {
							isIPv4 = true
						}
					}
				}

				if isIPv4 {
					s.parseIPv4(p.buf, p.count, p.remoteAddr)
				} else {
					s.handleHeaderlessIPv4(p.buf, p.count, p.listenIP, p.remoteAddr)
				}
			}
			// Return buffer to pool
			if cap(p.buf) >= 65536 {
				s.bufPool.Put(p.buf[:cap(p.buf)])
			}
		}
	}
}

func (s *Sniffer) startCollector(ctx context.Context, listenIP string) error {
	ipParsed := net.ParseIP(listenIP)
	isIPv6 := ipParsed.To4() == nil

	network := "ip4:ip"
	if isIPv6 {
		network = "ip6:ipv6"
	}

	pc, err := net.ListenPacket(network, listenIP)
	if err != nil {
		return fmt.Errorf("net.ListenPacket failed on %s: %v", listenIP, err)
	}
	defer pc.Close()

	// Get raw handle for ioctl
	rawConn, err := pc.(*net.IPConn).SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get SyscallConn for %s: %v", listenIP, err)
	}

	rawConn.Control(func(fd uintptr) {
		in := uint32(1) // RCVALL_ON
		var bytesReturned uint32
		// Call WSAIoctl via ws2_32.dll directly (syscall.WSAIoctl doesn't exist in Go)
		ws2, _ := syscall.LoadDLL("ws2_32.dll")
		if ws2 != nil {
			wsaIoctl, _ := ws2.FindProc("WSAIoctl")
			if wsaIoctl != nil {
				r1, _, e1 := wsaIoctl.Call(
					fd,
					uintptr(0x98000001), // SIO_RCVALL
					uintptr(unsafe.Pointer(&in)),
					uintptr(4),
					uintptr(0),
					uintptr(0),
					uintptr(unsafe.Pointer(&bytesReturned)),
					uintptr(0),
					uintptr(0),
				)
				if r1 != 0 {
					logger.Printf("[Sniffer] ⚠️  WSAIoctl(SIO_RCVALL) failed on %s: %v (UDP capture might be limited)\n", listenIP, e1)
				} else if s.Verbose {
					logger.Printf("[Sniffer] ✅ WSAIoctl(SIO_RCVALL) enabled on %s\n", listenIP)
				}
			}
		}
	})

	if s.Verbose {
		logger.Printf("[Sniffer] Collector active on %s. Waiting for packets...\n", listenIP)
	}

	var count uint64

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			buf := s.bufPool.Get().([]byte)
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				s.bufPool.Put(buf)
				time.Sleep(1 * time.Millisecond)
				continue
			}

			remoteAddr := "unknown"
			if addr != nil {
				remoteAddr = addr.String()
			}

			count++

			if s.Verbose && count%100 == 0 {
				logger.Printf("[Sniffer] [DEBUG] Captured packet %d on %s from %s (%d bytes)\n", count, listenIP, remoteAddr, n)
			}

			// Send to worker pool
			select {
			case s.ingestChan <- &rawPacket{
				buf:        buf[:n],
				count:      count,
				listenIP:   listenIP,
				remoteAddr: remoteAddr,
				isIPv6:     isIPv6,
			}:
			default:
				// Channel full, drop packet
				s.bufPool.Put(buf)
				if s.Verbose && count%100 == 0 {
					logger.Printf("[Sniffer] [Dropped] Ingest channel full!\n")
				}
			}
		}
	}
}

// isServerPort returns true if the port is a common service or game server port.
func isServerPort(port uint16) bool {
	// Common well-known ports
	if port < 1024 {
		return true
	}
	// Growtopia / ENet server ports
	if (port >= 17000 && port <= 17200) || port == 16000 {
		return true
	}
	// Common game ports (Steam, Minecraft, etc.)
	if port == 27015 || port == 27016 || port == 25565 {
		return true
	}
	return false
}

// isLoopbackOrLocal returns true if the given IP string is loopback or matches a local interface IP.
func (s *Sniffer) isLoopbackOrLocal(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true // treat unparseable as unreliable
	}
	if parsed.IsLoopback() {
		return true
	}
	return s.isLocalIP(ip)
}

func (s *Sniffer) handleHeaderlessIPv4(buf []byte, count uint64, localIP, remoteAddr string) {
	if len(buf) < 8 { // Minimum UDP/TCP header size
		return
	}

	srcPort := binary.BigEndian.Uint16(buf[0:2])
	dstPort := binary.BigEndian.Uint16(buf[2:4])

	// Strip port from remoteAddr if present (e.g. "1.2.3.4:1234" -> "1.2.3.4")
	// On Windows SIO_RCVALL, remoteAddr from ReadFrom is often unreliable for outgoing
	// packets — it may point to 0.0.0.0 or the local machine itself.
	remoteIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteIP = remoteAddr
	}

	srcIP := ""
	dstIP := ""

	// --- Connection Tracking Resolution (highest priority) ---
	// Case 1: outgoing packet — srcPort is our ephemeral port, dstPort is remote port.
	if resolved := s.lookupConnection(srcPort, dstPort); resolved != "" {
		srcIP = localIP
		dstIP = resolved
		if s.Verbose {
			logger.Printf("[Sniffer] [UDP-resolve] outgoing %s:%d -> %s:%d (connMap)\n",
				srcIP, srcPort, dstIP, dstPort)
		}
	}

	// Case 2: incoming packet — dstPort is our local port, srcPort is remote port.
	if srcIP == "" {
		if resolved := s.lookupConnection(dstPort, srcPort); resolved != "" {
			srcIP = resolved
			dstIP = localIP
			if s.Verbose {
				logger.Printf("[Sniffer] [UDP-resolve] incoming %s:%d -> %s:%d (connMap)\n",
					srcIP, srcPort, dstIP, dstPort)
			}
		}
	}

	// --- Fallback when connMap has no entry yet ---
	if srcIP == "" {
		// Determine direction via target-port list or heuristics
		isOutgoing := false
		isIncoming := false

		s.mu.RLock()
		for _, p := range s.targetPorts {
			if srcPort == p {
				isOutgoing = true
				break
			}
			if dstPort == p {
				isIncoming = true
				break
			}
		}
		s.mu.RUnlock()

		// Fallback heuristics if we don't know the client ports
		if !isOutgoing && !isIncoming {
			if isServerPort(srcPort) && !isServerPort(dstPort) {
				isIncoming = true
			} else if !isServerPort(srcPort) && isServerPort(dstPort) {
				isOutgoing = true
			} else if srcPort == 53 || dstPort == 53 {
				// Special case for DNS
				if srcPort == 53 {
					isIncoming = true
				} else {
					isOutgoing = true
				}
			} else {
				// Default to outgoing if ambiguous
				isOutgoing = true
			}
		}

		if s.SniffAll {
			finalSrcIP := ""
			finalDstIP := ""

			if s.isLocalIP(remoteIP) || remoteIP == "0.0.0.0" || remoteIP == "unknown" {
				// Both ends appear local or remote IP is unknown
				if isIncoming {
					finalSrcIP = "?"
					finalDstIP = localIP
				} else {
					finalSrcIP = localIP
					finalDstIP = "?"
				}
			} else {
				// remoteIP is usable as an external peer
				if isIncoming {
					finalSrcIP = remoteIP
					finalDstIP = localIP
				} else {
					finalSrcIP = localIP
					finalDstIP = remoteIP
				}
			}

			if finalSrcIP == localIP && (finalDstIP == "?" || finalDstIP == localIP) {
				low, high := srcPort, dstPort
				if low > high {
					low, high = high, low
				}
				s.portTrackerMu.Lock()
				if clientPort, exists := s.portTracker[low]; exists {
					if srcPort != clientPort {
						// This port didn't start the connection, likely it's a response
						finalSrcIP = "?"
						finalDstIP = localIP
					}
				} else {
					// First time seeing this pair, assume current srcPort is client
					s.portTracker[low] = srcPort
				}
				s.portTrackerMu.Unlock()
			}

			// Proactively track connection if we have a real remote IP
			if finalSrcIP != "?" && finalDstIP != "?" && finalSrcIP != "" && finalDstIP != "" {
				if finalSrcIP == localIP {
					s.trackConnection(srcPort, dstPort, finalDstIP)
				} else if finalDstIP == localIP {
					s.trackConnection(dstPort, srcPort, finalSrcIP)
				}
			}

			if finalSrcIP == "" {
				if isIncoming && remoteIP != "0.0.0.0" && remoteIP != "unknown" && !s.isLocalIP(remoteIP) {
					finalSrcIP = remoteIP
				} else {
					finalSrcIP = "?"
				}
			}
			if finalDstIP == "" {
				if !isIncoming && remoteIP != "0.0.0.0" && remoteIP != "unknown" && !s.isLocalIP(remoteIP) {
					finalDstIP = remoteIP
				} else {
					finalDstIP = "?"
				}
			}

			s.ingestPacket(buf, count, 17, finalSrcIP, finalDstIP, srcPort, dstPort, 0)
			return
		}

		// Detect protocol and buffer the packet for retroactive flush once IP is learned.
		var detectedHeaderLen int
		var detectedProto byte

		if len(buf) >= 20 {
			// 1. Check if it's TCP (TCP data-offset field at byte 12)
			dataOffset := buf[12] >> 4
			// For headerless packets, we also check if the flags/window look like TCP
			// and if the port numbers are plausible.
			if dataOffset >= 5 && int(dataOffset*4) <= len(buf) && int(dataOffset*4) >= 20 {
				detectedProto = 6 // TCP
				detectedHeaderLen = int(dataOffset * 4)
			}
		}
		if detectedProto == 0 {
			// Default to UDP but with some checks
			detectedProto = 17 // UDP
			detectedHeaderLen = 8
		}

		// Set pending tracking info
		var pendSrcIP, pendDstIP string
		var pendKey connKey
		if isIncoming {
			pendSrcIP = "?"
			pendDstIP = localIP
			pendKey = connKey{localPort: dstPort, remotePort: srcPort}
		} else {
			pendSrcIP = localIP
			pendDstIP = "?"
			pendKey = connKey{localPort: srcPort, remotePort: dstPort}
		}

		if s.Verbose && (count < 10 || count%100 == 0) {
			logger.Printf("[Sniffer] [UDP-pending] ports %d<->%d buffering until IP resolved\n",
				srcPort, dstPort)
		}

		s.bufferPending(pendKey, pendingPacket{
			buf:       buf,
			count:     count,
			proto:     detectedProto,
			srcIP:     pendSrcIP,
			dstIP:     pendDstIP,
			srcPort:   srcPort,
			dstPort:   dstPort,
			headerLen: detectedHeaderLen,
		})
		return // wait for retroactive flush
	}

	// 1. Check if it's TCP (TCP data-offset field at byte 12)
	if len(buf) >= 20 {
		dataOffset := buf[12] >> 4
		if dataOffset >= 5 && int(dataOffset*4) <= len(buf) && int(dataOffset*4) >= 20 {
			s.ingestPacket(buf, count, 6, srcIP, dstIP, srcPort, dstPort, 0)
			return
		}
	}

	// 2. Fallback: Assume UDP if ports are in range or if it doesn't look like TCP
	// (Especially for Growtopia/ENet which is almost always what we want if we're here)
	s.ingestPacket(buf, count, 17, srcIP, dstIP, srcPort, dstPort, 0)
}

func (s *Sniffer) parseIPv4(buf []byte, count uint64, remoteAddr string) {
	n := len(buf)
	if n < 20 {
		return
	}
	proto := buf[9]
	srcIP := net.IP(buf[12:16]).String()
	dstIP := net.IP(buf[16:20]).String()

	// If header IPs are unspecified (0.0.0.0), try using remoteAddr
	if srcIP == "0.0.0.0" && remoteAddr != "unknown" {
		srcIP = remoteAddr
	}

	headerLen := int(buf[0]&0x0F) * 4

	if n < headerLen+4 {
		return
	}

	if proto != 6 && proto != 17 {
		return
	}

	srcPort := binary.BigEndian.Uint16(buf[headerLen : headerLen+2])
	dstPort := binary.BigEndian.Uint16(buf[headerLen+2 : headerLen+4])

	// --- Connection Tracking: Learn real remote IPs from packets with full headers ---
	if s.isLocalIP(srcIP) && !s.isLocalIP(dstIP) {
		// Outgoing: our local port is srcPort, remote is dstIP:dstPort
		s.trackConnection(srcPort, dstPort, dstIP)
	} else if !s.isLocalIP(srcIP) && s.isLocalIP(dstIP) {
		// Incoming: our local port is dstPort, remote is srcIP:srcPort
		s.trackConnection(dstPort, srcPort, srcIP)
	}

	if s.checkTarget(srcPort, dstPort) {
		s.ingestPacket(buf, count, proto, srcIP, dstIP, srcPort, dstPort, headerLen)
	} else {
		s.checkBypass(dstIP, dstPort, proto)
	}
}

func (s *Sniffer) parseIPv6(buf []byte, count uint64, remoteAddr string) {
	n := len(buf)
	if n < 40 {
		return
	}

	// IPv6 Header: 40 bytes
	// Next Header is at byte 6
	proto := buf[6]
	srcIP := net.IP(buf[8:24]).String()
	dstIP := net.IP(buf[24:40]).String()

	if srcIP == "::" && remoteAddr != "unknown" {
		srcIP = remoteAddr
	}

	headerLen := 40

	if n < headerLen+4 {
		return
	}

	if proto != 6 && proto != 17 {
		return
	}

	srcPort := binary.BigEndian.Uint16(buf[headerLen : headerLen+2])
	dstPort := binary.BigEndian.Uint16(buf[headerLen+2 : headerLen+4])

	// --- Connection Tracking for IPv6 ---
	if s.isLocalIP(srcIP) && !s.isLocalIP(dstIP) {
		s.trackConnection(srcPort, dstPort, dstIP)
	} else if !s.isLocalIP(srcIP) && s.isLocalIP(dstIP) {
		s.trackConnection(dstPort, srcPort, srcIP)
	}

	if s.checkTarget(srcPort, dstPort) {
		s.ingestPacket(buf, count, proto, srcIP, dstIP, srcPort, dstPort, headerLen)
	} else {
		s.checkBypass(dstIP, dstPort, proto)
	}
}

func (s *Sniffer) checkBypass(dstIP string, dstPort uint16, proto byte) {
	s.mu.RLock()
	domain, ok := s.targetIPs[dstIP]
	s.mu.RUnlock()

	if !ok {
		return
	}

	// If we see traffic to a target IP that is NOT being redirected (i.e., not going to 127.0.0.1)
	// it's a bypass.
	s.lastWarningMu.Lock()
	if time.Since(s.lastWarning) > 5*time.Second {
		s.lastWarning = time.Now()
		s.lastWarningMu.Unlock()
		logger.Printf("\n[ALERT] Traffic to %s (%s) is BYPASSING the engine!\n", domain, dstIP)
		logger.Printf("[ALERT] -> REASON: DNS resolution bypassed our hosts file. Please disable 'Secure DNS' in Chrome.\n\n")
	} else {
		s.lastWarningMu.Unlock()
	}
}

func (s *Sniffer) checkTarget(srcPort, dstPort uint16) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// If we have target ports (from a PID), strictly follow them
	if len(s.targetPorts) > 0 {
		for _, p := range s.targetPorts {
			if srcPort == p || dstPort == p {
				return true
			}
		}
		return false
	}

	// Only then check for Global Capture (SniffAll)
	if s.SniffAll {
		return true
	}
	return false
}

func (s *Sniffer) ingestPacket(buf []byte, count uint64, protoNum byte, srcIP, dstIP string, srcPort, dstPort uint16, headerLen int) {

	n := len(buf)
	protocol := "UNKNOWN"
	l4HeaderLen := 0
	if protoNum == 6 {
		protocol = "TCP"
		if n < headerLen+14 {
			return
		}
		l4HeaderLen = int(buf[headerLen+12]>>4) * 4
	} else if protoNum == 17 {
		protocol = "UDP"
		l4HeaderLen = 8
	}

	if n < headerLen+l4HeaderLen {
		return
	}

	var localPort uint16
	if s.isLocalIP(srcIP) {
		localPort = srcPort
	} else {
		localPort = dstPort
	}

	s.pidMu.RLock()
	var pid uint32
	if protoNum == 6 { // TCP
		pid = s.tcpPortPidMap[localPort]
	} else if protoNum == 17 { // UDP
		pid = s.udpPortPidMap[localPort]
	}
	s.pidMu.RUnlock()

	processName := proc.GetProcessName(pid)

	s.connMu.RLock()
	domain := s.domainCache[srcIP]
	if domain == "" {
		domain = s.domainCache[dstIP]
	}
	s.connMu.RUnlock()

	if s.Verbose && (count < 10 || count%100 == 0) {
		domainInfo := ""
		if domain != "" {
			domainInfo = fmt.Sprintf(" [%s]", domain)
		}
		logger.Printf("[Sniffer] Ingesting %s packet: %s:%d -> %s:%d%s (payload %d bytes, PID %d [%s])\n",
			protocol, srcIP, srcPort, dstIP, dstPort, domainInfo, n-(headerLen+l4HeaderLen), pid, processName)
	}

	meta := make(map[string]interface{})
	if domain != "" {
		meta["domain"] = domain
	}
	if s.RawSniff {
		meta["raw"] = true
	}

	// Detect direction
	direction := "UNKNOWN"
	if srcIP == "?" {
		direction = "RESPONSE"
	} else if dstIP == "?" {
		direction = "REQUEST"
	} else if s.isLocalIP(srcIP) && !s.isLocalIP(dstIP) {
		direction = "REQUEST"
	} else if !s.isLocalIP(srcIP) && s.isLocalIP(dstIP) {
		direction = "RESPONSE"
	} else if s.isLocalIP(srcIP) && s.isLocalIP(dstIP) {
		// Heuristic for local-to-local: request if dstPort is target, response if srcPort is target
		isTargetDst := false
		isTargetSrc := false
		s.mu.RLock()
		for _, p := range s.targetPorts {
			if dstPort == p {
				isTargetDst = true
			}
			if srcPort == p {
				isTargetSrc = true
			}
		}
		s.mu.RUnlock()
		if isTargetDst && !isTargetSrc {
			direction = "REQUEST"
		} else if isTargetSrc && !isTargetDst {
			direction = "RESPONSE"
		}
	}
	meta["direction"] = direction

	// Deduplication: Ignore packets matching our own proxy listeners to avoid quadruple logging
	if s.isLocalIP(srcIP) || s.isLocalIP(dstIP) {
		s.mu.RLock()
		for _, targetPort := range s.targetPorts {
			if srcPort == targetPort || dstPort == targetPort {
				s.mu.RUnlock()
				return
			}
		}
		s.mu.RUnlock()
	}

	s.engine.Ingest(&engine.Packet{
		ID:          uint64(time.Now().UnixNano()),
		Timestamp:   time.Now().Unix(),
		Source:      srcIP,
		SourcePort:  srcPort,
		Dest:        dstIP,
		DestPort:    dstPort,
		Protocol:    protocol,
		Payload:     buf[headerLen+l4HeaderLen : n],
		PID:         pid,
		ProcessName: processName,
		Metadata:    meta,
	})
}
