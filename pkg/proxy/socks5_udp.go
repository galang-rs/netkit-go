package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
)

var (
	dnsCache   = make(map[string]net.IP)
	dnsCacheMu sync.RWMutex
)

func resolveUDPAddr(domain string) (net.IP, error) {
	dnsCacheMu.RLock()
	ip, ok := dnsCache[domain]
	dnsCacheMu.RUnlock()
	if ok {
		return ip, nil
	}

	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("failed to resolve domain: %v", err)
	}

	dnsCacheMu.Lock()
	dnsCache[domain] = ips[0]
	dnsCacheMu.Unlock()
	return ips[0], nil
}

// SOCKS5UDPHeader represents the 4+ byte header in SOCKS5 UDP packets
type SOCKS5UDPHeader struct {
	Reserved uint16
	Frag     uint8
	ATyp     uint8
	DstAddr  net.IP
	DstPort  uint16
}

// ParseSOCKS5UDPHeader extracts the target info from an encapsulated UDP packet
func ParseSOCKS5UDPHeader(data []byte) (*SOCKS5UDPHeader, []byte, error) {
	if len(data) < 10 {
		return nil, nil, fmt.Errorf("packet too short")
	}

	h := &SOCKS5UDPHeader{
		Reserved: binary.BigEndian.Uint16(data[0:2]),
		Frag:     data[2],
		ATyp:     data[3],
	}

	offset := 4
	switch h.ATyp {
	case 1: // IPv4
		h.DstAddr = net.IP(data[offset : offset+4])
		offset += 4
	case 3: // Domain
		length := int(data[offset])
		domain := string(data[offset+1 : offset+1+length])
		ip, err := resolveUDPAddr(domain)
		if err != nil {
			return nil, nil, err
		}
		h.DstAddr = ip
		offset += 1 + length
	case 4: // IPv6
		h.DstAddr = net.IP(data[offset : offset+16])
		offset += 16
	default:
		return nil, nil, fmt.Errorf("unsupported address type")
	}

	if len(data) < offset+2 {
		return nil, nil, fmt.Errorf("packet too short for port")
	}
	h.DstPort = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	return h, data[offset:], nil
}

// BuildSOCKS5UDPHeader creates the encapsulation header
func BuildSOCKS5UDPHeader(addr *net.UDPAddr) []byte {
	ip := addr.IP.To4()
	atyp := byte(1)
	if ip == nil {
		ip = addr.IP.To16()
		atyp = 4
	}

	header := make([]byte, 4+len(ip)+2)
	header[0] = 0x00
	header[1] = 0x00
	header[2] = 0x00 // No fragmentation support
	header[3] = atyp
	copy(header[4:], ip)
	binary.BigEndian.PutUint16(header[4+len(ip):], uint16(addr.Port))

	return header
}

// HandleUDPAssociate sets up a UDP relay point for a SOCKS5 client.
// It allocates a random port and starts a relay that decapsulates SOCKS5 UDP packets.
// The relay will automatically shut down when the provided context is canceled.
func HandleUDPAssociate(ctx context.Context, clientAddr string, tunnel *engine.TunnelConfig) (string, error) {
	// Force IPv4 for the relay listener to ensure compatibility with IPv4-only stacks (like Growtopia)
	laddr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
	if err != nil {
		return "", err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		// Fallback to default if udp4 fails
		conn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return "", err
		}
	}

	relayAddr := conn.LocalAddr().String()
	fmt.Printf("[SOCKS5] UDP Relay listening on %s (for client %s)\n", relayAddr, clientAddr)

	// Session management
	type udpSession struct {
		remoteConn   *net.UDPConn
		clientAddr   *net.UDPAddr
		lastActive   time.Time
		socks5Client *SOCKS5Client // Optional for chaining
		relayAddr    *net.UDPAddr  // Relay addr of upstream proxy
	}
	sessions := make(map[string]*udpSession)
	var mu sync.Mutex

	go func() {
		defer conn.Close()
		buf := make([]byte, 65535)

		// Monitor context for shutdown
		go func() {
			<-ctx.Done()
			conn.Close()
			mu.Lock()
			for _, s := range sessions {
				s.remoteConn.Close()
			}
			mu.Unlock()
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Increase read deadline to 5 seconds for smoother video buffering
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, srcAddr, err := conn.ReadFromUDP(buf)
				if err != nil {
					if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
						continue
					}
					return
				}

				header, payload, err := ParseSOCKS5UDPHeader(buf[:n])
				if err != nil {
					fmt.Printf("[SOCKS5-UDP] ❌ Failed to parse header from %s: %v\n", srcAddr, err)
					continue
				}

				targetAddr := &net.UDPAddr{IP: header.DstAddr, Port: int(header.DstPort)}
				targetKey := targetAddr.String()

				mu.Lock()
				session, ok := sessions[targetKey]
				if !ok {
					var remoteConn *net.UDPConn
					var s5Client *SOCKS5Client
					var upstreamRelay *net.UDPAddr

					if tunnel != nil && (strings.HasPrefix(tunnel.URL, "socks5://") || strings.HasPrefix(tunnel.URL, "socks5h://")) {
						// UDP Proxy Chaining
						s5Client, err = NewSOCKS5Client(tunnel.URL)
						if err == nil {
							upstreamRelay, err = s5Client.ConnectUDP(ctx)
							if err == nil {
								fmt.Printf("[SOCKS5-UDP] 🔗 Chaining UDP through upstream proxy relay: %s\n", upstreamRelay)
								remoteConn, err = net.DialUDP("udp", nil, upstreamRelay)
							}
						}
						if err != nil {
							fmt.Printf("[SOCKS5-UDP] ❌ Failed to setup tunnel: %v. Falling back to direct.\n", err)
							if s5Client != nil {
								s5Client.Close()
								s5Client = nil
							}
							remoteConn, err = net.DialUDP("udp", nil, targetAddr)
						}
					} else {
						remoteConn, err = net.DialUDP("udp", nil, targetAddr)
					}

					if err != nil {
						mu.Unlock()
						continue
					}
					session = &udpSession{
						remoteConn:   remoteConn,
						clientAddr:   srcAddr,
						lastActive:   time.Now(),
						socks5Client: s5Client,
						relayAddr:    upstreamRelay,
					}
					sessions[targetKey] = session

					// Start response relay for this session
					go func(s *udpSession, tAddr *net.UDPAddr) {
						respBuf := make([]byte, 65535)
						defer s.remoteConn.Close()
						if s.socks5Client != nil {
							defer s.socks5Client.Close()
						}
						for {
							select {
							case <-ctx.Done():
								return
							default:
								// Increase read deadline to 5 seconds for smoother video buffering
								_ = s.remoteConn.SetReadDeadline(time.Now().Add(5 * time.Second))
								rn, _, err := s.remoteConn.ReadFromUDP(respBuf)
								if err != nil {
									if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
										continue
									}
									fmt.Printf("[SOCKS5-UDP] ❌ Remote read error: %v\n", err)
									mu.Lock()
									delete(sessions, tAddr.String())
									mu.Unlock()
									return
								}

								var responsePayload []byte
								var actualSrc *net.UDPAddr
								if s.socks5Client != nil {
									// Unwrap the upstream response
									actualSrc, responsePayload, err = UnwrapUDPHeader(respBuf[:rn])
									if err != nil {
										continue
									}
								} else {
									responsePayload = respBuf[:rn]
									actualSrc = tAddr
								}

								mu.Lock()
								activeClient := s.clientAddr
								mu.Unlock()

								s.lastActive = time.Now()
								h := BuildSOCKS5UDPHeader(actualSrc)
								full := append(h, responsePayload...)
								_, _ = conn.WriteToUDP(full, activeClient)
							}
						}
					}(session, targetAddr)
				}
				session.clientAddr = srcAddr
				mu.Unlock()

				session.lastActive = time.Now()
				if session.socks5Client != nil {
					// Wrap for upstream
					wrapped := WrapUDPHeader(targetAddr, payload)
					_, _ = session.remoteConn.Write(wrapped)
				} else {
					_, _ = session.remoteConn.Write(payload)
				}
			}
		}
	}()

	return relayAddr, nil
}
