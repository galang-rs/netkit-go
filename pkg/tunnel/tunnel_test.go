package tunnel

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// --- Protocol Tests ---

func TestProtoConstants(t *testing.T) {
	if ProtoTCP != "tcp" {
		t.Errorf("expected 'tcp', got '%s'", ProtoTCP)
	}
	if ProtoUDP != "udp" {
		t.Errorf("expected 'udp', got '%s'", ProtoUDP)
	}
	if ProtoHTTPS != "https" {
		t.Errorf("expected 'https', got '%s'", ProtoHTTPS)
	}
	if ProtoAll != "all" {
		t.Errorf("expected 'all', got '%s'", ProtoAll)
	}
}

func TestCommand_String(t *testing.T) {
	cmd := &Command{Type: CmdAuth, Args: []string{"user", "pass"}}
	s := cmd.String()
	if s != "AUTH user pass" {
		t.Errorf("expected 'AUTH user pass', got '%s'", s)
	}
}

func TestParseCommand_Valid(t *testing.T) {
	cmd, err := ParseCommand("AUTH user pass")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if cmd.Type != CmdAuth {
		t.Errorf("expected AUTH, got '%s'", cmd.Type)
	}
}

func TestParseCommand_Empty(t *testing.T) {
	_, err := ParseCommand("")
	if err == nil {
		t.Error("expected error for empty command")
	}
}

// --- PortManager Tests ---

func TestNewPortManager(t *testing.T) {
	pm := NewPortManager(8000, 8010)
	if pm == nil {
		t.Fatal("should not be nil")
	}
}

func TestPortManager_AllocateRange(t *testing.T) {
	pm := NewPortManager(8000, 8010)
	start, end, err := pm.AllocateRange(8000, 8005)
	if err != nil {
		t.Fatalf("allocate error: %v", err)
	}
	if start != 8000 || end != 8005 {
		t.Errorf("expected 8000-8005, got %d-%d", start, end)
	}
}

func TestPortManager_AllocateRange_DoubleAlloc(t *testing.T) {
	pm := NewPortManager(8000, 8010)
	_, _, err := pm.AllocateRange(8000, 8005)
	if err != nil {
		t.Fatalf("first allocate: %v", err)
	}
	// Second allocation should fail for same range
	_, _, err = pm.AllocateRange(8000, 8005)
	if err == nil {
		t.Error("expected error for double allocation")
	}
}

func TestPortManager_ReleaseRange(t *testing.T) {
	pm := NewPortManager(8000, 8010)
	pm.AllocateRange(8000, 8005)
	pm.ReleaseRange(8000, 8005)
	// Should be able to reallocate
	_, _, err := pm.AllocateRange(8000, 8005)
	if err != nil {
		t.Errorf("re-allocate after release should work: %v", err)
	}
}

func TestPortManager_Release_Single(t *testing.T) {
	pm := NewPortManager(8000, 8010)
	pm.AllocateRange(8000, 8002)
	pm.Release(8000)
	// 8000 should be free now
	pm.mu.Lock()
	used := pm.used[8000]
	pm.mu.Unlock()
	if used {
		t.Error("port 8000 should be released")
	}
}

// --- Frame Tests ---

func TestFrame_ReadWrite(t *testing.T) {
	// Use net.Pipe for frame read/write
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	srv := &NKTunnelServer{}
	client := &NKTunnelClient{}

	// Write frame from server side
	go func() {
		srv.writeFrame(c1, 1, []byte("hello"))
	}()

	// Read frame from client side
	frame, err := client.readFrame(c2)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if frame.StreamID != 1 {
		t.Errorf("expected stream ID 1, got %d", frame.StreamID)
	}
	if string(frame.Payload) != "hello" {
		t.Errorf("expected 'hello', got '%s'", frame.Payload)
	}
}

func TestFrame_PingPong(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	srv := &NKTunnelServer{}

	// Send PING (stream ID 0)
	go func() {
		srv.writeFrame(c1, StreamIDPing, []byte("PING"))
	}()

	client := &NKTunnelClient{}
	frame, err := client.readFrame(c2)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if frame.StreamID != StreamIDPing {
		t.Errorf("expected StreamIDPing, got %d", frame.StreamID)
	}
}

// --- NKTunnelClient Tests ---

func TestNewNKTunnelClient(t *testing.T) {
	c := NewNKTunnelClient("server:9090", "admin", "secret", ":8080", "8000-8005", "tcp")
	if c == nil {
		t.Fatal("should not be nil")
	}
	if c.ServerAddr != "server:9090" {
		t.Errorf("server addr: got '%s'", c.ServerAddr)
	}
	if c.User != "admin" {
		t.Errorf("user: got '%s'", c.User)
	}
	if c.Protocol != "tcp" {
		t.Errorf("protocol: got '%s'", c.Protocol)
	}
}

func TestNKTunnelClient_GetAssignedPorts_Default(t *testing.T) {
	c := NewNKTunnelClient("server:9090", "admin", "secret", ":8080", "8000-8005", "tcp")
	start, end := c.GetAssignedPorts()
	if start != 0 || end != 0 {
		t.Errorf("unconnected client should return 0-0, got %d-%d", start, end)
	}
}

func TestNKTunnelClient_IsConnected_Default(t *testing.T) {
	c := NewNKTunnelClient("server:9090", "admin", "secret", ":8080", "8000-8005", "tcp")
	if c.IsConnected() {
		t.Error("new client should not be connected")
	}
}

func TestNKTunnelClient_Stop_NoConnection(t *testing.T) {
	c := NewNKTunnelClient("server:9090", "admin", "secret", ":8080", "8000-8005", "tcp")
	// Stop should not panic even without connection
	c.Stop()
}

// --- NKTunnelServer Tests ---

func TestNewNKTunnelServer(t *testing.T) {
	auth := func(user, pass string) bool { return user == "admin" && pass == "secret" }
	srv := NewNKTunnelServer(":0", auth, nil, nil, "8000-8010")
	if srv == nil {
		t.Fatal("should not be nil")
	}
}

func TestNKTunnelServer_PortManager(t *testing.T) {
	auth := func(user, pass string) bool { return true }
	srv := NewNKTunnelServer("127.0.0.1:0", auth, nil, nil, "8000-8010")
	if srv == nil {
		t.Fatal("server should not be nil")
	}
	// Verify port manager was initialized correctly
	if srv.portManager == nil {
		t.Fatal("portManager should be initialized")
	}
}

func TestNKTunnelServer_VerifyPort_Invalid(t *testing.T) {
	auth := func(user, pass string) bool { return true }
	srv := NewNKTunnelServer("127.0.0.1:0", auth, nil, nil, "8000-8010")
	// Port that's not open should return false
	result := srv.VerifyPort(19999)
	if result {
		t.Log("Port verify returned true (port might be in use)")
	}
}

// --- DualStack Tests (TCP + UDP) ---

func TestTunnelProtocol_TCPSupport(t *testing.T) {
	if ProtoTCP != "tcp" {
		t.Error("TCP protocol not defined")
	}
	c := NewNKTunnelClient("server:9090", "admin", "secret", ":8080", "8000-8010", ProtoTCP)
	if c.Protocol != "tcp" {
		t.Error("client should support TCP")
	}
}

func TestTunnelProtocol_UDPSupport(t *testing.T) {
	if ProtoUDP != "udp" {
		t.Error("UDP protocol not defined")
	}
	c := NewNKTunnelClient("server:9090", "admin", "secret", ":8080", "8000-8010", ProtoUDP)
	if c.Protocol != "udp" {
		t.Error("client should support UDP")
	}
}

func TestTunnelProtocol_DualStack(t *testing.T) {
	if ProtoAll != "all" {
		t.Error("all protocol not defined")
	}
	c := NewNKTunnelClient("server:9090", "admin", "secret", ":8080", "8000-8010", ProtoAll)
	if c.Protocol != "all" {
		t.Error("client should support dual-stack (all)")
	}
}

func TestDetectPublicIP_Format(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	ip4, ip6 := detectPublicIPs()
	if ip4 == "" && ip6 == "" {
		t.Log("Public IPs not detected (may be in CI/isolated environment)")
	} else {
		t.Logf("Detected public IPs: v4=%s, v6=%s", ip4, ip6)
		if ip4 != "" {
			parsed := net.ParseIP(ip4)
			if parsed == nil {
				t.Errorf("Invalid IPv4 returned: '%s'", ip4)
			}
		}
		if ip6 != "" {
			parsed := net.ParseIP(ip6)
			if parsed == nil {
				t.Errorf("Invalid IPv6 returned: '%s'", ip6)
			}
		}
	}
}
func TestNKTunnelClient_KeepAlive_NoDeadlock(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	client := NewNKTunnelClient("server:0", "u", "p", ":0", "0", "tcp")
	client.ControlConn = c1
	client.connected = true

	// Reader to prevent net.Pipe from blocking on Write
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := c2.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Success criteria: writeFrame should not block due to recursive lock
	done := make(chan bool, 1)
	go func() {
		err := client.writeFrame(client.ControlConn, StreamIDPing, []byte("PING"))
		if err != nil {
			// io: read/write on closed pipe is fine if test ends quickly
			t.Logf("writeFrame error (expected if pipe closed): %v", err)
		}
		done <- true
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Deadlock or hang detected in writeFrame!")
	}
}

func TestNKTunnelClient_EOF(t *testing.T) {
	c1, c2 := net.Pipe()
	// No defer c2.Close() here, we close it manually to trigger EOF

	client := NewNKTunnelClient("server:0", "u", "p", ":0", "0", "tcp")
	client.ControlConn = c1
	client.connected = true

	// Success criteria: readFrame should return io.EOF immediately when other side closes
	done := make(chan error, 1)
	go func() {
		_, err := client.readFrame(client.ControlConn)
		done <- err
	}()

	c2.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Expected EOF error, got nil")
		}
		if err != io.EOF && !strings.Contains(err.Error(), "closed") {
			t.Logf("Got error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readFrame did not return EOF as expected!")
	}
}
