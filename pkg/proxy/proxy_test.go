package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
)

// --- Relay Tests ---

func TestNewRelay(t *testing.T) {
	e := engine.New()
	relay := NewRelay(e, "example.com", true)
	if relay == nil {
		t.Fatal("NewRelay should return non-nil")
	}
	if relay.Hostname != "example.com" {
		t.Errorf("expected hostname 'example.com', got '%s'", relay.Hostname)
	}
	if !relay.Decrypted {
		t.Error("Decrypted should be true")
	}
}

func TestRelay_RegisterConn(t *testing.T) {
	e := engine.New()
	relay := NewRelay(e, "test.com", false)
	info := &engine.ConnInfo{
		Type:   "socks5",
		Source: "192.168.1.100:1234",
		Dest:   "example.com:443",
	}
	relay.RegisterConn(info)
	if relay.Conn == nil {
		t.Error("Conn should be set after RegisterConn")
	}
	if relay.Conn.Type != "socks5" {
		t.Errorf("expected type 'socks5', got '%s'", relay.Conn.Type)
	}
}

func TestRelay_BiDirectional(t *testing.T) {
	e := engine.New()
	relay := NewRelay(e, "relay-test.com", false)

	clientConn, proxyClientSide := net.Pipe()
	proxyServerSide, serverConn := net.Pipe()

	defer clientConn.Close()
	defer serverConn.Close()

	go relay.Start(proxyClientSide, proxyServerSide)

	testData := []byte("Hello from client")
	go func() {
		clientConn.Write(testData)
		time.Sleep(100 * time.Millisecond)
		clientConn.Close()
	}()

	buf := make([]byte, 1024)
	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("server read error: %v", err)
	}
	if string(buf[:n]) != string(testData) {
		t.Errorf("expected '%s', got '%s'", testData, buf[:n])
	}
	serverConn.Close()
}

// --- SOCKS5 UDP Tests ---

func TestParseSOCKS5UDPHeader_IPv4(t *testing.T) {
	data := []byte{
		0x00, 0x00, // Reserved
		0x00,             // Frag
		0x01,             // ATyp = IPv4
		192, 168, 1, 100, // IP
		0x00, 0x50, // Port 80
		'H', 'i', // Payload
	}

	header, payload, err := ParseSOCKS5UDPHeader(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if header.ATyp != 1 {
		t.Errorf("expected ATyp 1, got %d", header.ATyp)
	}
	if header.DstPort != 80 {
		t.Errorf("expected port 80, got %d", header.DstPort)
	}
	if header.DstAddr.String() != "192.168.1.100" {
		t.Errorf("expected IP 192.168.1.100, got %s", header.DstAddr)
	}
	if string(payload) != "Hi" {
		t.Errorf("expected payload 'Hi', got '%s'", payload)
	}
}

func TestParseSOCKS5UDPHeader_IPv6(t *testing.T) {
	// Build proper SOCKS5 UDP IPv6 packet:
	// [2 reserved][1 frag][1 atyp=4][16 IPv6][2 port][payload]
	data := []byte{
		0x00, 0x00, // Reserved
		0x00, // Frag
		0x04, // ATyp = IPv6 (4)
	}
	// IPv6 address ::1 (16 bytes, last byte = 1)
	ipv6 := make([]byte, 16)
	ipv6[15] = 1
	data = append(data, ipv6...)
	// Port 80
	data = append(data, 0x00, 0x50)
	// Payload
	data = append(data, 'X')

	header, payload, err := ParseSOCKS5UDPHeader(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if header.ATyp != 4 {
		t.Errorf("expected ATyp 4, got %d", header.ATyp)
	}
	if header.DstPort != 80 {
		t.Errorf("expected port 80, got %d", header.DstPort)
	}
	if string(payload) != "X" {
		t.Errorf("expected payload 'X', got '%s'", string(payload))
	}
}

func TestParseSOCKS5UDPHeader_TooShort(t *testing.T) {
	_, _, err := ParseSOCKS5UDPHeader([]byte{0x00, 0x01})
	if err == nil {
		t.Error("expected error for too-short packet")
	}
}

func TestBuildSOCKS5UDPHeader_IPv4(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 8080}
	header := BuildSOCKS5UDPHeader(addr)
	if len(header) != 10 {
		t.Errorf("expected 10 bytes, got %d", len(header))
	}
	if header[3] != 0x01 {
		t.Errorf("expected ATyp 1 (IPv4), got %d", header[3])
	}
}

func TestBuildSOCKS5UDPHeader_IPv6(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 443}
	header := BuildSOCKS5UDPHeader(addr)
	if len(header) != 22 {
		t.Errorf("expected 22 bytes for IPv6, got %d", len(header))
	}
	if header[3] != 0x04 {
		t.Errorf("expected ATyp 4 (IPv6), got %d", header[3])
	}
}

// --- UniversalDialer Tests ---

func TestUniversalDialer_UnsupportedWG(t *testing.T) {
	d := &UniversalDialer{Tunnel: &engine.TunnelConfig{Type: "wg", WGConfig: "test"}}
	_, err := d.Dial("tcp", "example.com:443")
	if err == nil {
		t.Error("WG should return error (not implemented)")
	}
}

// --- HTTP Proxy Support Tests ---

func TestHTTPProxyListener_SupportsHTTPConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		if len(line) >= 7 && line[:7] == "CONNECT" {
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	resp := string(buf[:n])
	if resp != "HTTP/1.1 200 OK\r\n\r\n" {
		t.Errorf("unexpected response: %s", resp)
	}
}

// --- GetLocalIPForRelay Tests ---

func TestGetLocalIPForRelay_NotEmpty(t *testing.T) {
	ip := GetLocalIPForRelay()
	if ip == "" {
		t.Error("should return non-empty IP")
	}
}

func TestGetLocalIPForRelay_ValidIP(t *testing.T) {
	ip := GetLocalIPForRelay()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Errorf("invalid IP: %s", ip)
	}
}

// --- formatAddr Tests ---

func TestFormatAddr(t *testing.T) {
	addr := formatAddr("10.0.0.1", 8080)
	if addr != "10.0.0.1:8080" {
		t.Errorf("expected '10.0.0.1:8080', got '%s'", addr)
	}
}

func TestFormatAddr_Zero(t *testing.T) {
	addr := formatAddr("0.0.0.0", 0)
	if addr != "0.0.0.0:0" {
		t.Errorf("expected '0.0.0.0:0', got '%s'", addr)
	}
}

// --- BufferedConn Tests ---

func TestBufferedConn_Read(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	reader := bufio.NewReader(c2)
	bc := &BufferedConn{Conn: c2, Reader: reader}

	go func() {
		c1.Write([]byte("test data"))
		c1.Close()
	}()

	buf := make([]byte, 64)
	n, err := bc.Read(buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if string(buf[:n]) != "test data" {
		t.Errorf("expected 'test data', got '%s'", buf[:n])
	}
}

// --- HandleUDPAssociate Test ---

func TestHandleUDPAssociate_AllocatesPort(t *testing.T) {
	addr, err := HandleUDPAssociate(context.Background(), "127.0.0.1:12345", nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if addr == "" {
		t.Error("address should not be empty")
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("invalid address: %v", err)
	}
	if portStr == "0" {
		t.Error("should allocate a real port, not 0")
	}
	fmt.Printf("[Test] UDP relay allocated at: %s\n", addr)
}
