package capture

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bacot120211/netkit-go/pkg/adblock"
	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/protocol/tls"
	"github.com/bacot120211/netkit-go/pkg/proxy"
	"github.com/bacot120211/netkit-go/pkg/security"
)

// HandleSOCKS5Shared contains the core SOCKS5 handshake and relay logic.
// It can be used by both SOCKS5Listener and HTTPProxyListener (polyglot support).
func HandleSOCKS5Shared(conn net.Conn, r *bufio.Reader, e engine.Engine, tlsInt *tls.TLSInterceptor, logPrefix string, tunnel *engine.TunnelConfig, shouldMITM func(string) bool, user, pass string, bl *security.BruteforceLimiter) {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// 0. Security: Bruteforce Check
	if bl != nil && !bl.IsAllowed(remoteIP) {
		logger.Warnf("[%s] 🚫 BANNED IP attempted connection: %s\n", logPrefix, remoteIP)
		return
	}

	// 1. SOCKS5 Method Negotiation
	buf := make([]byte, 256)
	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		logger.Printf("[%s] ❌ Read negotiation error: %v\n", logPrefix, err)
		return
	}
	if buf[0] != 0x05 {
		logger.Printf("[%s] ❌ Invalid version: 0x%02x\n", logPrefix, buf[0])
		return
	}
	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(r, methods); err != nil {
		logger.Printf("[%s] ❌ Read methods error: %v\n", logPrefix, err)
		return
	}

	selectedMethod := byte(0xFF) // No acceptable methods
	if user == "" && pass == "" {
		// If no auth required, look for 0x00
		for _, m := range methods {
			if m == 0x00 {
				selectedMethod = 0x00
				break
			}
		}
	} else {
		// If auth required, look for 0x02 (Username/Password)
		for _, m := range methods {
			if m == 0x02 {
				selectedMethod = 0x02
				break
			}
		}
	}

	if _, err := conn.Write([]byte{0x05, selectedMethod}); err != nil {
		logger.Printf("[%s] ❌ Selection write error: %v\n", logPrefix, err)
		return
	}

	if selectedMethod == 0xFF {
		logger.Printf("[%s] ❌ No acceptable methods offered\n", logPrefix)
		return
	}

	// 1.1 Username/Password Authentication (Method 0x02)
	if selectedMethod == 0x02 {
		// Read version (0x01)
		if _, err := io.ReadFull(r, buf[:1]); err != nil {
			return
		}
		// Read user len
		if _, err := io.ReadFull(r, buf[:1]); err != nil {
			return
		}
		uLen := int(buf[0])
		uBuf := make([]byte, uLen)
		if _, err := io.ReadFull(r, uBuf); err != nil {
			return
		}
		// Read pass len
		if _, err := io.ReadFull(r, buf[:1]); err != nil {
			return
		}
		pLen := int(buf[0])
		pBuf := make([]byte, pLen)
		if _, err := io.ReadFull(r, pBuf); err != nil {
			return
		}

		if string(uBuf) != user || string(pBuf) != pass {
			logger.Printf("[%s] ❌ Authentication failed for user: %s (IP: %s)\n", logPrefix, string(uBuf), remoteIP)
			if bl != nil {
				bl.RecordFailure(remoteIP)
			}
			_, _ = conn.Write([]byte{0x01, 0x01}) // Version 1, Status 1 (failure)
			return
		}

		// Success
		if bl != nil {
			bl.RecordSuccess(remoteIP)
		}
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	}

	// 2. SOCKS5 Request
	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		logger.Printf("[%s] ❌ Read request error: %v\n", logPrefix, err)
		return
	}
	command := buf[1]
	atyp := buf[3]

	var host string
	switch atyp {
	case 0x01: // IPv4
		if _, err := io.ReadFull(r, buf[:4]); err != nil {
			logger.Printf("[%s] ❌ Read IPv4 error: %v\n", logPrefix, err)
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // Domain
		if _, err := io.ReadFull(r, buf[:1]); err != nil {
			logger.Printf("[%s] ❌ Read domain len error: %v\n", logPrefix, err)
			return
		}
		length := int(buf[0])
		if _, err := io.ReadFull(r, buf[:length]); err != nil {
			logger.Printf("[%s] ❌ Read domain error: %v\n", logPrefix, err)
			return
		}
		host = string(buf[:length])
	case 0x04: // IPv6
		if _, err := io.ReadFull(r, buf[:16]); err != nil {
			logger.Printf("[%s] ❌ Read IPv6 error: %v\n", logPrefix, err)
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		logger.Printf("[%s] ❌ Unsupported atyp: 0x%02x\n", logPrefix, atyp)
		return
	}

	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		logger.Printf("[%s] ❌ Read port error: %v\n", logPrefix, err)
		return
	}
	port := int(buf[0])<<8 | int(buf[1])
	target := fmt.Sprintf("%s:%d", host, port)

	logger.Printf("[%s] 🎯 %s %s from %s\n", logPrefix, func() string {
		switch command {
		case 0x01:
			return "CONNECT"
		case 0x02:
			return "BIND"
		case 0x03:
			return "UDP_ASSOC"
		default:
			return fmt.Sprintf("CMD(0x%02x)", command)
		}
	}(), target, conn.RemoteAddr())

	// 3. Trigger JS OnConnect for all commands to allow dynamic routing
	bc := &proxy.BufferedConn{Conn: conn, Reader: r}
	localAddr := conn.LocalAddr().String()
	localHost, _, _ := net.SplitHostPort(localAddr)

	connInfo := &engine.ConnInfo{
		Type:    "socks5",
		Source:  bc.RemoteAddr().String(),
		Dest:    target,
		IP:      bc.RemoteAddr().String(),
		Through: engine.GetIPType(localHost),
	}

	if cfg := e.OnConnect(connInfo); cfg != nil {
		if strings.ToLower(cfg.Type) == "drop" {
			logger.Printf("[%s] 🚫 Connection dropped by OnConnect for %s\n", logPrefix, bc.RemoteAddr())
			// Return SOCKS5 error 0x04 (Host unreachable)
			// This often maps to CURLE_COULDNT_RESOLVE_HOST (6) in curl/browsers
			_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		tunnel = cfg
	}

	if command == 0x01 { // CONNECT
		// Send success response
		resp := []byte{0x05, 0x00, 0x00}
		localAddr := conn.LocalAddr().String()
		lHost, lPortStr, _ := net.SplitHostPort(localAddr)
		lPort, _ := strconv.ParseUint(lPortStr, 10, 16)

		if ip := net.ParseIP(lHost); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				resp = append(resp, 0x01)
				resp = append(resp, ip4...)
			} else {
				resp = append(resp, 0x04)
				resp = append(resp, ip.To16()...)
			}
		} else {
			resp = append(resp, 0x01, 0, 0, 0, 0) // Fallback
		}
		resp = append(resp, byte(lPort>>8), byte(lPort&0xFF))

		if _, err := conn.Write(resp); err != nil {
			logger.Printf("[%s] ❌ Success signal error: %v\n", logPrefix, err)
			return
		}

		// Ad-Blocking Check (Silvence MITM Error noise)
		if res, matches := adblock.GetEngine().Match("", host); matches {
			logger.Printf("[%s] 🚫 Blocked Ad Connection: %s (%s: %s)\n", logPrefix, target, res.Category, res.Reason)
			return
		}

		if port == 443 {
			// MITM TLS ONLY if shouldMITM returns true
			// If target is an IP (e.g. redirected via hosts), we hand off to MITM anyway
			// so the interceptor can peek the SNI and recover the real hostname.
			isIP := net.ParseIP(host) != nil
			isLocal := host == "127.0.0.1" || host == "::1" || host == "localhost"

			if (shouldMITM != nil && shouldMITM(host)) || isIP || isLocal {
				hostname := host
				logger.Printf("[%s] 🔓 Handing off %s to MITM Interceptor (SNI Peek enabled for IPs)\n", logPrefix, target)
				if err := tlsInt.HandleMITM(bc, target, hostname, nil, tunnel, connInfo); err != nil {
					logger.Printf("[%s] ❌ MITM Error for %s: %v\n", logPrefix, target, err)
				}
				return
			}
			logger.Printf("[%s] ⏩ Skipping MITM for %s (not in sniff list)\n", logPrefix, target)
			// Fallback to TCP Relay
		}

		// TCP Relay for everything else
		dialer := &proxy.UniversalDialer{Tunnel: tunnel}
		dialAddr := target
		if realIP, ok := tlsInt.ResolvedIPs[host]; ok {
			dialAddr = net.JoinHostPort(realIP, fmt.Sprintf("%d", port))
		}

		// HAIRPIN NAT BYPASS: If the target matches our own listener address (public IP),
		// dial 127.0.0.1 instead to avoid being dropped by firewall/cloud NAT.
		if lAddr := conn.LocalAddr(); lAddr != nil {
			_, lPortStr, _ := net.SplitHostPort(lAddr.String())
			if dialAddr == lAddr.String() || (host == GetLocalIP() && fmt.Sprintf("%d", port) == lPortStr) {
				logger.Printf("[%s] 🔄 Local hairpin detected for %s, bypassing to 127.0.0.1:%s\n", logPrefix, dialAddr, lPortStr)
				dialAddr = net.JoinHostPort("127.0.0.1", lPortStr)
			}
		}

		dst, err := dialer.Dial("tcp", dialAddr)
		if err != nil {
			logger.Printf("[%s] ❌ Dial %s (resolved: %s) error: %v\n", logPrefix, target, dialAddr, err)
			return
		}
		defer dst.Close()

		logger.Printf("[%s] ↔️  Relaying plain TCP for %s\n", logPrefix, target)
		relay := proxy.NewRelay(e, target, false)
		relay.RegisterConn(connInfo)
		relay.Start(bc, dst)
	} else if command == 0x02 { // BIND
		// SOCKS5 BIND is typically used for active-mode FTP.
		// 1. Listen on a random port.
		l, portStr, err := proxy.HandleBIND(host)
		if err != nil {
			logger.Printf("[%s] ❌ BIND listen error: %v\n", logPrefix, err)
			_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}

		var port uint16
		fmt.Sscanf(portStr, "%d", &port)

		// Send the FIRST success response with the port we're listening on.
		resp1 := []byte{0x05, 0x00, 0x00}
		localAddr := conn.LocalAddr().String()
		lHost, _, _ := net.SplitHostPort(localAddr)

		if ip := net.ParseIP(lHost); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				resp1 = append(resp1, 0x01)
				resp1 = append(resp1, ip4...)
			} else {
				resp1 = append(resp1, 0x04)
				resp1 = append(resp1, ip.To16()...)
			}
		} else {
			resp1 = append(resp1, 0x01, 0, 0, 0, 0)
		}
		resp1 = append(resp1, byte(port>>8), byte(port&0xFF))

		if _, err := conn.Write(resp1); err != nil {
			l.Close()
			return
		}

		logger.Printf("[%s] ⏳ BIND waiting for target %s on port %s\n", logPrefix, host, portStr)

		// 2. Wait for incoming connection from the target.
		targetConn, err := proxy.WaitForBindConnection(l, host, 30*time.Second)
		if err != nil {
			logger.Printf("[%s] ❌ BIND wait error: %v\n", logPrefix, err)
			_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer targetConn.Close()

		// Send the SECOND success response with the address of the target.
		remoteIPStr, remotePortStr, _ := net.SplitHostPort(targetConn.RemoteAddr().String())
		remoteIP := net.ParseIP(remoteIPStr)
		var rPort uint16
		fmt.Sscanf(remotePortStr, "%d", &rPort)

		resp2 := []byte{0x05, 0x00, 0x00}
		if ip4 := remoteIP.To4(); ip4 != nil {
			resp2 = append(resp2, 0x01)
			resp2 = append(resp2, ip4...)
		} else {
			resp2 = append(resp2, 0x04)
			resp2 = append(resp2, remoteIP.To16()...)
		}
		resp2 = append(resp2, byte(rPort>>8), byte(rPort&0xFF))
		if _, err := conn.Write(resp2); err != nil {
			return
		}

		// 3. Relay.
		relay := proxy.NewRelay(e, target, false)
		relay.RegisterConn(connInfo)
		relay.Start(bc, targetConn)
	} else if command == 0x03 { // UDP ASSOCIATE
		// Create a context that is canceled when the TCP connection closes
		relayCtx, cancel := context.WithCancel(context.Background())
		defer cancel()

		relayAddr, err := proxy.HandleUDPAssociate(relayCtx, conn.RemoteAddr().String(), tunnel)
		if err != nil {
			logger.Printf("[%s] ❌ UDP_ASSOC error: %v\n", logPrefix, err)
			_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}

		_, rPort, _ := net.SplitHostPort(relayAddr)
		var p uint16
		fmt.Sscanf(rPort, "%d", &p)

		// Determine local IP to return to client
		resp := []byte{0x05, 0x00, 0x00}
		localAddr := conn.LocalAddr().String()
		lHost, _, _ := net.SplitHostPort(localAddr)

		// Prefer IPv4 if possible to avoid IPv6 loopback (::1) issues with IPv4 clients
		lIP := net.ParseIP(lHost)
		if lIP != nil && lIP.IsUnspecified() {
			// If listening on 0.0.0.0, use the IP the client used to connect to us
			remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			if rip := net.ParseIP(remoteHost); rip != nil {
				// We need the local IP on the interface that received the connection
				// For now, let's use a helper to get the BEST local IP
				if localIP := proxy.GetLocalIPForRelay(); localIP != "" {
					lIP = net.ParseIP(localIP)
				}
			}
		}

		if lIP != nil && lIP.To4() != nil {
			resp = append(resp, 0x01)
			resp = append(resp, lIP.To4()...)
		} else if lIP != nil && lIP.To16() != nil {
			// If we are on [::1], we should probably return 127.0.0.1 if the client is connecting via loopback
			if lIP.IsLoopback() {
				resp = append(resp, 0x01, 127, 0, 0, 1)
			} else {
				resp = append(resp, 0x04)
				resp = append(resp, lIP.To16()...)
			}
		} else {
			resp = append(resp, 0x01, 127, 0, 0, 1) // Safe default for local
		}
		resp = append(resp, byte(p>>8), byte(p&0xFF))
		if _, err := conn.Write(resp); err != nil {
			return
		}

		// Keep connection open - if TCP closes, context is canceled via defer cancel()
		// and UDP relay is shut down.
		tempBuf := make([]byte, 1)
		for {
			if _, err := conn.Read(tempBuf); err != nil {
				return
			}
		}
	} else {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}
