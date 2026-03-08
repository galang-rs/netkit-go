package capture

import (
	"net"
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

// --- GetLocalIP ---

func TestGetLocalIP_NotEmpty(t *testing.T) {
	ip := GetLocalIP()
	if ip == "" {
		t.Error("GetLocalIP should return a non-empty string")
	}
}

func TestGetLocalIP_ValidIP(t *testing.T) {
	ip := GetLocalIP()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Errorf("GetLocalIP returned unparseable IP: '%s'", ip)
	}
}

func TestGetLocalIP_IPv4(t *testing.T) {
	ip := GetLocalIP()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("GetLocalIP returned unparseable IP: '%s'", ip)
	}
	if parsed.To4() == nil {
		t.Log("GetLocalIP returned IPv6 instead of IPv4 (acceptable but unexpected)")
	}
}

// --- isServerPort ---

func TestIsServerPort_HTTP(t *testing.T) {
	if !isServerPort(80) {
		t.Error("Port 80 should be recognized as a server port")
	}
}

func TestIsServerPort_HTTPS(t *testing.T) {
	if !isServerPort(443) {
		t.Error("Port 443 should be recognized as a server port")
	}
}

func TestIsServerPort_SSH(t *testing.T) {
	if !isServerPort(22) {
		t.Error("Port 22 should be recognized as a server port")
	}
}

func TestIsServerPort_DNS(t *testing.T) {
	if !isServerPort(53) {
		t.Error("Port 53 should be recognized as a server port")
	}
}

func TestIsServerPort_HighEphemeral(t *testing.T) {
	if isServerPort(55555) {
		t.Error("Port 55555 should NOT be recognized as a server port")
	}
}

func TestIsServerPort_Zero(t *testing.T) {
	// Port 0 is < 1024, so isServerPort returns true
	if !isServerPort(0) {
		t.Error("Port 0 is below 1024, so isServerPort should return true")
	}
}

// --- NewSniffer ---

func TestNewSniffer_SkipAdmin(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping: requires administrator privileges (raw sockets)")
	}
	e := engine.New()
	s := NewSniffer([]string{"127.0.0.1"}, e)
	if s == nil {
		t.Fatal("NewSniffer should return non-nil")
	}
}

func TestNewSniffer_SniffAllDefault(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping: requires administrator privileges")
	}
	e := engine.New()
	s := NewSniffer([]string{"127.0.0.1"}, e)
	if s.SniffAll {
		t.Error("SniffAll should be false by default")
	}
}

// --- NewTCPListener ---

func TestNewTCPListener_Fields(t *testing.T) {
	e := engine.New()
	l := NewTCPListener(":8080", "10.0.0.1:80", e)
	if l == nil {
		t.Fatal("NewTCPListener should return non-nil")
	}
	if l.addr != ":8080" {
		t.Errorf("Expected addr ':8080', got '%s'", l.addr)
	}
	if l.targetAddr != "10.0.0.1:80" {
		t.Errorf("Expected targetAddr '10.0.0.1:80', got '%s'", l.targetAddr)
	}
}

func TestNewTCPListener_EngineSet(t *testing.T) {
	e := engine.New()
	l := NewTCPListener(":9090", "10.0.0.2:443", e)
	if l.engine == nil {
		t.Error("Engine should be set")
	}
}

// --- Sniffer SetLocalIPs ---

func TestSniffer_SetLocalIPs_SkipAdmin(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping: requires administrator privileges")
	}
	e := engine.New()
	s := NewSniffer([]string{"127.0.0.1"}, e)
	s.SetLocalIPs([]string{"127.0.0.1", "192.168.1.100"})
	if !s.isLocalIP("127.0.0.1") {
		t.Error("127.0.0.1 should be recognized as local IP")
	}
	if !s.isLocalIP("192.168.1.100") {
		t.Error("192.168.1.100 should be recognized as local IP")
	}
	if s.isLocalIP("8.8.8.8") {
		t.Error("8.8.8.8 should NOT be recognized as local IP")
	}
}

// --- Sniffer UpdatePorts ---

func TestSniffer_UpdatePorts_SkipAdmin(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping: requires administrator privileges")
	}
	e := engine.New()
	s := NewSniffer([]string{"127.0.0.1"}, e)
	s.UpdatePorts([]uint16{80, 443, 8080})
	if !s.checkTarget(80, 9999) {
		t.Error("Port 80 should be a target after UpdatePorts")
	}
	if !s.checkTarget(9999, 443) {
		t.Error("Port 443 should be a target after UpdatePorts")
	}
}

// --- Sniffer ResetPorts ---

func TestSniffer_ResetPorts_SkipAdmin(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping: requires administrator privileges")
	}
	e := engine.New()
	s := NewSniffer([]string{"127.0.0.1"}, e)
	s.UpdatePorts([]uint16{80, 443})
	s.ResetPorts()
	// After reset, targetPorts should be empty
	if s.checkTarget(80, 9999) {
		t.Error("Port 80 should NOT be a target after ResetPorts")
	}
}

// --- Sniffer AddDomainMapping ---

func TestSniffer_AddDomainMapping_SkipAdmin(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping: requires administrator privileges")
	}
	e := engine.New()
	s := NewSniffer([]string{"127.0.0.1"}, e)
	s.SetBypassDetection(make(map[string]string))
	s.AddDomainMapping("1.2.3.4", "example.com")
	// Should not panic — functionality verified by not crashing
}
