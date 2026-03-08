package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"
)

var (
	clientDNSCache   = make(map[string]net.IP)
	clientDNSCacheMu sync.RWMutex
)

func resolveClientUDPAddr(domain string) (net.IP, error) {
	clientDNSCacheMu.RLock()
	ip, ok := clientDNSCache[domain]
	clientDNSCacheMu.RUnlock()
	if ok {
		return ip, nil
	}

	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("failed to resolve domain: %v", err)
	}

	clientDNSCacheMu.Lock()
	clientDNSCache[domain] = ips[0]
	clientDNSCacheMu.Unlock()
	return ips[0], nil
}

// SOCKS5Client handles the client-side of a SOCKS5 association,
// specifically for UDP ASSOCIATE commands.
type SOCKS5Client struct {
	ProxyURL   *url.URL
	UDPConn    *net.UDPConn
	TCPControl net.Conn
	RelayAddr  *net.UDPAddr
}

// NewSOCKS5Client creates a new SOCKS5 client for the given proxy URL.
func NewSOCKS5Client(proxyURLStr string) (*SOCKS5Client, error) {
	u, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil, err
	}
	return &SOCKS5Client{ProxyURL: u}, nil
}

// ConnectUDP performs the SOCKS5 handshake and requests a UDP association.
// It returns the relay address that the client should send UDP packets to.
func (c *SOCKS5Client) ConnectUDP(ctx context.Context) (*net.UDPAddr, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", c.ProxyURL.Host)
	if err != nil {
		return nil, err
	}
	c.TCPControl = conn

	// 1. Version identifier/method selection message
	methods := []byte{0x05, 0x01, 0x00}
	if c.ProxyURL.User != nil {
		methods = []byte{0x05, 0x02, 0x00, 0x02}
	}
	if _, err := conn.Write(methods); err != nil {
		return nil, err
	}

	// 2. Method selection
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	if reply[0] != 0x05 {
		return nil, fmt.Errorf("invalid SOCKS version: 0x%02x", reply[0])
	}

	if reply[1] == 0x02 { // Username/Password
		user := c.ProxyURL.User.Username()
		pass, _ := c.ProxyURL.User.Password()
		req := []byte{0x01, byte(len(user))}
		req = append(req, []byte(user)...)
		req = append(req, byte(len(pass)))
		req = append(req, []byte(pass)...)
		if _, err := conn.Write(req); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(conn, reply); err != nil {
			return nil, err
		}
		if reply[1] != 0x00 {
			return nil, fmt.Errorf("SOCKS5 auth failed: 0x%02x", reply[1])
		}
	} else if reply[1] != 0x00 {
		return nil, fmt.Errorf("unsupported SOCKS5 auth method: 0x%02x", reply[1])
	}

	// 3. UDP ASSOCIATE request
	// We send 0.0.0.0:0 to let the proxy decide or use the TCP connection's source.
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	// 4. UDP ASSOCIATE reply
	reply = make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	if reply[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 UDP Associate failed: 0x%02x", reply[1])
	}

	var bndAddr net.IP
	atyp := reply[3]
	switch atyp {
	case 1: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		bndAddr = net.IP(addr)
	case 3: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		addr := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		ips, err := net.LookupIP(string(addr))
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("failed to resolve BND.ADDR: %v", err)
		}
		bndAddr = ips[0]
	case 4: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		bndAddr = net.IP(addr)
	default:
		return nil, fmt.Errorf("unsupported address type in SOCKS5 reply: 0x%02x", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	bndPort := binary.BigEndian.Uint16(portBuf)

	// If BND.ADDR is unspecified, use the proxy host.
	if bndAddr.IsUnspecified() {
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		bndAddr = net.ParseIP(host)
	}

	c.RelayAddr = &net.UDPAddr{IP: bndAddr, Port: int(bndPort)}
	return c.RelayAddr, nil
}

// Close closes the control connection.
func (c *SOCKS5Client) Close() error {
	if c.TCPControl != nil {
		return c.TCPControl.Close()
	}
	return nil
}

// WrapUDPHeader adds a SOCKS5 UDP header to the payload with the given target address.
func WrapUDPHeader(target *net.UDPAddr, payload []byte) []byte {
	ip := target.IP.To4()
	atyp := byte(1)
	if ip == nil {
		ip = target.IP.To16()
		atyp = 4
	}
	if ip == nil {
		return payload // Should not happen
	}

	header := make([]byte, 4+len(ip)+2)
	header[0], header[1], header[2] = 0, 0, 0
	header[3] = atyp
	copy(header[4:], ip)
	binary.BigEndian.PutUint16(header[4+len(ip):], uint16(target.Port))

	return append(header, payload...)
}

// UnwrapUDPHeader removes the SOCKS5 UDP header and returns the source address and payload.
func UnwrapUDPHeader(data []byte) (*net.UDPAddr, []byte, error) {
	if len(data) < 10 {
		return nil, nil, fmt.Errorf("packet too short")
	}

	atyp := data[3]
	var addr net.IP
	var offset int

	switch atyp {
	case 1: // IPv4
		addr = net.IP(data[4:8])
		offset = 8
	case 3: // Domain
		length := int(data[4])
		domain := string(data[5 : 5+length])
		ip, err := resolveClientUDPAddr(domain)
		if err != nil {
			return nil, nil, err
		}
		addr = ip
		offset = 5 + length
	case 4: // IPv6
		addr = net.IP(data[4:20])
		offset = 20
	default:
		return nil, nil, fmt.Errorf("unsupported atyp: 0x%02x", atyp)
	}

	if len(data) < offset+2 {
		return nil, nil, fmt.Errorf("packet too short for port")
	}

	port := binary.BigEndian.Uint16(data[offset : offset+2])
	return &net.UDPAddr{IP: addr, Port: int(port)}, data[offset+2:], nil
}
