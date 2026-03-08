// Package cgnat provides CGNAT (Carrier-Grade NAT) bypass functionality.
// It detects NAT type, performs UDP hole-punching, and falls back to relay
// for Symmetric NAT. Supports all ISPs/carriers across mobile, WiFi, and ethernet.
package cgnat

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// STUN Message Types (RFC 5389)
const (
	stunBindingRequest  = 0x0001
	stunBindingResponse = 0x0101
	stunBindingError    = 0x0111

	// STUN Attributes
	attrMappedAddress    = 0x0001
	attrChangeRequest    = 0x0003
	attrSourceAddress    = 0x0004
	attrChangedAddress   = 0x0005
	attrXORMappedAddress = 0x0020
	attrOtherAddress     = 0x802C

	// Change Request flags
	changeIP   = 0x04
	changePort = 0x02

	// STUN magic cookie (RFC 5389)
	magicCookie = 0x2112A442
)

// STUNResult contains the result of a STUN binding request.
type STUNResult struct {
	MappedAddr   *net.UDPAddr // Public IP:port as seen by STUN server
	SourceAddr   *net.UDPAddr // STUN server's source address
	ChangedAddr  *net.UDPAddr // STUN server's alternate address
	LocalAddr    *net.UDPAddr // Local address used
	ResponseTime time.Duration
}

// DefaultSTUNServers is a list of public STUN servers for NAT detection.
var DefaultSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
	"stun.stunprotocol.org:3478",
	"stun.voip.blackberry.com:3478",
}

// STUNClient performs STUN binding requests for NAT detection.
type STUNClient struct {
	Timeout time.Duration
}

// NewSTUNClient creates a STUN client with default settings.
func NewSTUNClient() *STUNClient {
	return &STUNClient{Timeout: 3 * time.Second}
}

// Bind sends a STUN Binding Request and returns the mapped address.
func (c *STUNClient) Bind(serverAddr string, conn *net.UDPConn) (*STUNResult, error) {
	return c.bindWithFlags(serverAddr, conn, 0)
}

// BindChangeIP sends a STUN Binding Request with CHANGE-REQUEST (change IP).
func (c *STUNClient) BindChangeIP(serverAddr string, conn *net.UDPConn) (*STUNResult, error) {
	return c.bindWithFlags(serverAddr, conn, changeIP|changePort)
}

// BindChangePort sends a STUN Binding Request with CHANGE-REQUEST (change port only).
func (c *STUNClient) BindChangePort(serverAddr string, conn *net.UDPConn) (*STUNResult, error) {
	return c.bindWithFlags(serverAddr, conn, changePort)
}

func (c *STUNClient) bindWithFlags(serverAddr string, conn *net.UDPConn, changeFlags byte) (*STUNResult, error) {
	addr, err := net.ResolveUDPAddr("udp4", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve STUN server %s: %w", serverAddr, err)
	}

	// Build STUN Binding Request
	txID := make([]byte, 12)
	if _, err := rand.Read(txID); err != nil {
		return nil, fmt.Errorf("generate transaction ID: %w", err)
	}

	msg := buildSTUNRequest(txID, changeFlags)

	// Set deadline
	if err := conn.SetDeadline(time.Now().Add(c.Timeout)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}
	defer conn.SetDeadline(time.Time{}) // clear deadline

	start := time.Now()

	// Send request
	if _, err := conn.WriteTo(msg, addr); err != nil {
		return nil, fmt.Errorf("send STUN request: %w", err)
	}

	// Read response
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("read STUN response: %w", err)
	}

	elapsed := time.Since(start)

	result, err := parseSTUNResponse(buf[:n], txID)
	if err != nil {
		return nil, err
	}
	result.ResponseTime = elapsed
	result.LocalAddr = conn.LocalAddr().(*net.UDPAddr)

	return result, nil
}

// buildSTUNRequest creates a STUN Binding Request message.
func buildSTUNRequest(txID []byte, changeFlags byte) []byte {
	hasChangeReq := changeFlags != 0
	attrLen := 0
	if hasChangeReq {
		attrLen = 8 // 4 bytes header + 4 bytes value
	}

	// Header: Type(2) + Length(2) + Magic Cookie(4) + Transaction ID(12) = 20 bytes
	msg := make([]byte, 20+attrLen)
	binary.BigEndian.PutUint16(msg[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(msg[2:4], uint16(attrLen))
	binary.BigEndian.PutUint32(msg[4:8], magicCookie)
	copy(msg[8:20], txID)

	if hasChangeReq {
		// CHANGE-REQUEST attribute
		binary.BigEndian.PutUint16(msg[20:22], attrChangeRequest)
		binary.BigEndian.PutUint16(msg[22:24], 4)
		msg[24] = 0
		msg[25] = 0
		msg[26] = 0
		msg[27] = changeFlags
	}

	return msg
}

// parseSTUNResponse parses a STUN Binding Response.
func parseSTUNResponse(data []byte, expectedTxID []byte) (*STUNResult, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("STUN response too short: %d bytes", len(data))
	}

	msgType := binary.BigEndian.Uint16(data[0:2])
	msgLen := binary.BigEndian.Uint16(data[2:4])

	if msgType == stunBindingError {
		return nil, fmt.Errorf("STUN server returned error response")
	}
	if msgType != stunBindingResponse {
		return nil, fmt.Errorf("unexpected STUN message type: 0x%04x", msgType)
	}

	// Verify transaction ID
	for i := 0; i < 12; i++ {
		if data[8+i] != expectedTxID[i] {
			return nil, fmt.Errorf("STUN transaction ID mismatch")
		}
	}

	result := &STUNResult{}

	// Parse attributes
	pos := 20
	end := 20 + int(msgLen)
	if end > len(data) {
		end = len(data)
	}

	for pos+4 <= end {
		attrType := binary.BigEndian.Uint16(data[pos : pos+2])
		attrLen := binary.BigEndian.Uint16(data[pos+2 : pos+4])
		pos += 4

		if pos+int(attrLen) > end {
			break
		}

		attrData := data[pos : pos+int(attrLen)]

		switch attrType {
		case attrMappedAddress:
			addr := parseMappedAddress(attrData)
			if addr != nil {
				result.MappedAddr = addr
			}
		case attrXORMappedAddress:
			addr := parseXORMappedAddress(attrData, data[4:8], data[8:20])
			if addr != nil {
				result.MappedAddr = addr // XOR takes priority
			}
		case attrSourceAddress:
			addr := parseMappedAddress(attrData)
			if addr != nil {
				result.SourceAddr = addr
			}
		case attrChangedAddress, attrOtherAddress:
			addr := parseMappedAddress(attrData)
			if addr != nil {
				result.ChangedAddr = addr
			}
		}

		// Align to 4-byte boundary
		pos += int(attrLen)
		if pad := attrLen % 4; pad != 0 {
			pos += int(4 - pad)
		}
	}

	if result.MappedAddr == nil {
		return nil, fmt.Errorf("no mapped address in STUN response")
	}

	return result, nil
}

// parseMappedAddress parses MAPPED-ADDRESS or SOURCE-ADDRESS attribute.
func parseMappedAddress(data []byte) *net.UDPAddr {
	if len(data) < 8 {
		return nil
	}
	family := data[1]
	port := binary.BigEndian.Uint16(data[2:4])

	if family == 0x01 { // IPv4
		ip := net.IPv4(data[4], data[5], data[6], data[7])
		return &net.UDPAddr{IP: ip, Port: int(port)}
	} else if family == 0x02 { // IPv6
		if len(data) < 20 {
			return nil
		}
		ip := make(net.IP, 16)
		copy(ip, data[4:20])
		return &net.UDPAddr{IP: ip, Port: int(port)}
	}
	return nil
}

// parseXORMappedAddress parses XOR-MAPPED-ADDRESS attribute (RFC 5389).
func parseXORMappedAddress(data []byte, cookie []byte, txID []byte) *net.UDPAddr {
	if len(data) < 8 {
		return nil
	}
	family := data[1]
	xPort := binary.BigEndian.Uint16(data[2:4])
	port := xPort ^ uint16(binary.BigEndian.Uint32(cookie)>>16)

	if family == 0x01 { // IPv4
		xIP := binary.BigEndian.Uint32(data[4:8])
		ip := xIP ^ binary.BigEndian.Uint32(cookie)
		return &net.UDPAddr{
			IP:   net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)),
			Port: int(port),
		}
	} else if family == 0x02 { // IPv6
		if len(data) < 20 {
			return nil
		}
		xIP := data[4:20]
		ip := make(net.IP, 16)
		// RFC 5389: XOR with concatenation of magic cookie and transaction ID
		xor := append(cookie, txID...)
		for i := 0; i < 16; i++ {
			ip[i] = xIP[i] ^ xor[i]
		}
		return &net.UDPAddr{IP: ip, Port: int(port)}
	}
	return nil
}
