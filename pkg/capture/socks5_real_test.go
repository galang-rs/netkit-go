package capture

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/protocol/tls"
)

func TestSOCKS5Real_ProductFlow(t *testing.T) {
	// 1. Start a dummy target server (Echo server)
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start target server: %v", err)
	}
	defer targetLn.Close()
	targetAddr := targetLn.Addr().String()

	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn) // Echo back everything
	}()

	// 2. Start SOCKS5 Proxy
	e := engine.New() // Real engine
	ca, _ := tls.NewCA()
	// Use 127.0.0.1:0 to get a random free port
	proxy := NewSOCKS5Listener("127.0.0.1:0", ca, e, nil)
	if err := proxy.Listen(); err != nil {
		t.Fatalf("Failed to listen proxy: %v", err)
	}
	defer proxy.Close()
	proxyAddr := proxy.listener.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := proxy.Serve(ctx); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			// Ignore closed connection error on shutdown
		}
	}()

	// Give a small time for proxy to start (although Serve is backgrounded)
	time.Sleep(100 * time.Millisecond)

	// 3. Connect via SOCKS5 Client (Manual Handshake)
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 4. SOCKS5 Handshake (No Auth)
	// VER=0x05, NMETHODS=0x01, METHODS=0x00
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		t.Fatalf("Failed to write handshake: %v", err)
	}

	resp := make([]byte, 2)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		t.Fatalf("Failed to read handshake response: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("Invalid handshake response: %x", resp)
	}

	// 5. SOCKS5 CONNECT to dummy target
	tHost, tPortStr, _ := net.SplitHostPort(targetAddr)
	tIP := net.ParseIP(tHost).To4()
	var tPort uint16
	fmt.Sscanf(tPortStr, "%d", &tPort)

	req := []byte{0x05, 0x01, 0x00, 0x01} // CONNECT, RSV, ATYP=IPv4
	req = append(req, tIP...)
	req = append(req, byte(tPort>>8), byte(tPort&0xFF))

	_, err = conn.Write(req)
	if err != nil {
		t.Fatalf("Failed to write CONNECT request: %v", err)
	}

	// Read CONNECT response (Success)
	resp = make([]byte, 10)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		t.Fatalf("Failed to read CONNECT response: %v", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("SOCKS5 CONNECT failed with rep: 0x%02x", resp[1])
	}

	// 6. Test Data Relay (Echo)
	testMsg := "Hello NetKit-Go SOCKS5 Product!"
	_, err = conn.Write([]byte(testMsg))
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	readBuf := make([]byte, len(testMsg))
	_, err = io.ReadFull(conn, readBuf)
	if err != nil {
		t.Fatalf("Failed to read echoed data: %v", err)
	}

	if string(readBuf) != testMsg {
		t.Errorf("Data corruption! Expected %q, got %q", testMsg, string(readBuf))
	} else {
		t.Logf("Success! Data relayed correctly: %s", string(readBuf))
	}
}
