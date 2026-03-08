package interceptor

import (
	"os"
	"runtime"
	"testing"

	"github.com/bacot120211/netkit-go/pkg/engine"
)

func isAdmin() bool {
	if runtime.GOOS != "windows" {
		return true
	}
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// --- TransparentInterceptor ---

func TestTransparentInterceptor_Name(t *testing.T) {
	e := engine.New()
	ti := NewTransparentInterceptor(e)
	name := ti.Name()
	if name != "Driverless Transparent Interceptor" {
		t.Errorf("Expected 'Driverless Transparent Interceptor', got '%s'", name)
	}
}

func TestTransparentInterceptor_OnConnect_ReturnsNil(t *testing.T) {
	e := engine.New()
	ti := NewTransparentInterceptor(e)
	result := ti.OnConnect(&engine.ConnInfo{
		Type:   "http",
		Source: "10.0.0.1",
		Dest:   "10.0.0.2",
	})
	if result != nil {
		t.Error("OnConnect should return nil")
	}
}

func TestTransparentInterceptor_OnPacket_SetsMetadata(t *testing.T) {
	e := engine.New()
	ti := NewTransparentInterceptor(e)

	pkt := &engine.Packet{
		Protocol: "TCP",
		Source:   "10.0.0.1",
		Dest:     "10.0.0.2",
	}
	ctx := &engine.PacketContext{
		Packet: pkt,
	}

	err := ti.OnPacket(ctx)
	if err != nil {
		t.Fatalf("OnPacket should not error: %v", err)
	}
	if pkt.Metadata == nil {
		t.Fatal("Metadata should be initialized")
	}
	if pkt.Metadata["Transparent"] != true {
		t.Error("Metadata['Transparent'] should be true")
	}
}

func TestTransparentInterceptor_OnPacket_ExistingMetadata(t *testing.T) {
	e := engine.New()
	ti := NewTransparentInterceptor(e)

	pkt := &engine.Packet{
		Protocol: "TCP",
		Source:   "10.0.0.1",
		Dest:     "10.0.0.2",
		Metadata: map[string]interface{}{"existing": "value"},
	}
	ctx := &engine.PacketContext{
		Packet: pkt,
	}

	ti.OnPacket(ctx)
	if pkt.Metadata["existing"] != "value" {
		t.Error("Existing metadata should be preserved")
	}
	if pkt.Metadata["Transparent"] != true {
		t.Error("Metadata['Transparent'] should be set")
	}
}

func TestTransparentInterceptor_Start_SkipAdmin(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping: requires administrator privileges")
	}
	e := engine.New()
	ti := NewTransparentInterceptor(e)
	err := ti.Start()
	if err != nil {
		t.Errorf("Start should not error when admin: %v", err)
	}
}

func TestTransparentInterceptor_RedirectTCP_SkipAdmin(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping: requires administrator privileges (netsh)")
	}
	e := engine.New()
	ti := NewTransparentInterceptor(e)
	// Use a high ephemeral port to avoid conflicts
	err := ti.RedirectTCP("127.0.0.1", 59999, "127.0.0.1", 59998)
	if err != nil {
		t.Errorf("RedirectTCP should not error when admin: %v", err)
	}
	// Cleanup
	ti.Cleanup()
}

func TestTransparentInterceptor_Cleanup_Empty(t *testing.T) {
	e := engine.New()
	ti := NewTransparentInterceptor(e)
	// Should not panic with no active rules
	ti.Cleanup()
}

// --- JA3Interceptor ---

func TestJA3Interceptor_Name(t *testing.T) {
	j := &JA3Interceptor{}
	name := j.Name()
	if name != "JA3 Fingerprinter" {
		t.Errorf("Expected 'JA3 Fingerprinter', got '%s'", name)
	}
}

func TestJA3Interceptor_OnConnect_ReturnsNil(t *testing.T) {
	j := &JA3Interceptor{}
	result := j.OnConnect(&engine.ConnInfo{
		Type:   "http",
		Source: "10.0.0.1",
		Dest:   "10.0.0.2",
	})
	if result != nil {
		t.Error("OnConnect should return nil")
	}
}

func TestJA3Interceptor_OnPacket_NonTLS(t *testing.T) {
	j := &JA3Interceptor{}

	pkt := &engine.Packet{
		Protocol: "HTTP",
		Payload:  []byte("GET / HTTP/1.1\r\n"),
	}
	ctx := &engine.PacketContext{
		Packet: pkt,
	}

	err := j.OnPacket(ctx)
	if err != nil {
		t.Fatalf("OnPacket should not error: %v", err)
	}
	// Non-TLS packets should not have JA3 metadata
	if pkt.Metadata != nil {
		if _, ok := pkt.Metadata["JA3Hash"]; ok {
			t.Error("Non-TLS packet should not have JA3Hash")
		}
	}
}

func TestJA3Interceptor_OnPacket_TCPNonTLSData(t *testing.T) {
	j := &JA3Interceptor{}

	pkt := &engine.Packet{
		Protocol: "TCP",
		Payload:  []byte("plaintext data"),
	}
	ctx := &engine.PacketContext{
		Packet: pkt,
	}

	err := j.OnPacket(ctx)
	if err != nil {
		t.Fatalf("OnPacket should not error: %v", err)
	}
	// Plain TCP data is not a TLS ClientHello, so no JA3 metadata
	if pkt.Metadata != nil {
		if _, ok := pkt.Metadata["JA3Hash"]; ok {
			t.Error("Plain TCP data should not have JA3Hash")
		}
	}
}

func TestJA3Interceptor_OnPacket_TLSProtocol(t *testing.T) {
	j := &JA3Interceptor{}

	// A minimal non-ClientHello TLS record
	pkt := &engine.Packet{
		Protocol: "TLS",
		Payload:  []byte{0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
	}
	ctx := &engine.PacketContext{
		Packet: pkt,
	}

	err := j.OnPacket(ctx)
	if err != nil {
		t.Fatalf("OnPacket should not error for TLS application data: %v", err)
	}
	// Application data (0x17) is not a ClientHello, JA3 should be empty
}
