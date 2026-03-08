package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
)

type DNSSpoofer struct {
	mu          sync.RWMutex
	hosts       map[string]string // domain -> ip
	upstreamDNS string
	engine      engine.Engine
}

func NewDNSSpoofer(e engine.Engine) *DNSSpoofer {
	return &DNSSpoofer{
		hosts:       make(map[string]string),
		upstreamDNS: "8.8.8.8:53",
		engine:      e,
	}
}

func (d *DNSSpoofer) AddHost(domain, ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hosts[domain] = ip
}

func (d *DNSSpoofer) Start(ctx context.Context) error {
	// Listen on UDP 53
	conn, err := net.ListenPacket("udp", ":53")
	if err != nil {
		return fmt.Errorf("failed to listen on DNS port: %w", err)
	}
	defer conn.Close()

	fmt.Println("[DNS] DNS Spoofing service active on :53")

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				fmt.Printf("[DNS] Error reading: %v\n", err)
				continue
			}
		}

		go d.handleQuery(conn, addr, buf[:n])
	}
}

func (d *DNSSpoofer) handleQuery(conn net.PacketConn, addr net.Addr, data []byte) {
	// Simple DNS parser/responder (MVP)
	// For a full implementation, use something like github.com/miekg/dns
	// Since we don't have it in go.mod, we'll implement enough to spoof.

	if len(data) < 12 {
		return
	}

	// Transaction ID (2 bytes)
	// Flags (2 bytes)
	// Questions (2 bytes)
	// ...

	// Extract domain (naive implementation)
	domain := ""
	pos := 12
	for {
		if pos >= len(data) {
			break
		}
		length := int(data[pos])
		if length == 0 {
			break
		}
		if domain != "" {
			domain += "."
		}
		domain += string(data[pos+1 : pos+1+length])
		pos += 1 + length
	}

	d.mu.RLock()
	spoofIP, exists := d.hosts[domain]
	d.mu.RUnlock()

	if exists {
		fmt.Printf("[DNS] Spoofing query for %s -> %s\n", domain, spoofIP)
		// Generate spoofed response
		resp := d.buildResponse(data, spoofIP)
		conn.WriteTo(resp, addr)
	} else {
		// Forward to upstream
		d.forwardQuery(conn, addr, data)
	}
}

func (d *DNSSpoofer) buildResponse(query []byte, ip string) []byte {
	// Build a standard DNS A Record response
	// This is a minimal implementation
	resp := make([]byte, len(query))
	copy(resp, query)

	// Set response flags: 0x8180 (Standard query response, No error)
	resp[2] = 0x81
	resp[3] = 0x80

	// Set Answer Count to 1
	resp[7] = 1

	// Append Answer Section
	// Name: Offset to query name (0xc00c)
	// Type: A (0x0001)
	// Class: IN (0x0001)
	// TTL: 60s (0x0000003c)
	// Length: 4 (0x0004)
	// IP: ...
	answer := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04}
	ipParsed := net.ParseIP(ip).To4()
	answer = append(answer, ipParsed...)

	return append(resp, answer...)
}

func (d *DNSSpoofer) forwardQuery(conn net.PacketConn, clientAddr net.Addr, data []byte) {
	daddr, _ := net.ResolveUDPAddr("udp", d.upstreamDNS)
	outConn, err := net.DialUDP("udp", nil, daddr)
	if err != nil {
		return
	}
	defer outConn.Close()

	outConn.Write(data)
	buf := make([]byte, 1024)
	outConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := outConn.Read(buf)
	if err == nil {
		conn.WriteTo(buf[:n], clientAddr)
	}
}
