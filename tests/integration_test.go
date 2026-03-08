package tests

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/manager"
	"github.com/bacot120211/netkit-go/pkg/mem"
	"github.com/bacot120211/netkit-go/pkg/protocol/dtls"
	"github.com/bacot120211/netkit-go/pkg/protocol/stack"
	"github.com/bacot120211/netkit-go/pkg/proxy"
	"github.com/bacot120211/netkit-go/pkg/security"
)

// ==========================================
// QA AUTOMATION TESTS
// Full integration test suite: activates
// features, runs them, and validates behavior.
// ==========================================

type testLog struct {
	mu      sync.Mutex
	entries []string
}

func (tl *testLog) Log(msg string) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.entries = append(tl.entries, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05.000"), msg))
}

func (tl *testLog) Dump(t *testing.T) {
	t.Helper()
	tl.mu.Lock()
	defer tl.mu.Unlock()
	for _, e := range tl.entries {
		t.Log(e)
	}
}

// ==========================================
// 1. CLI Args — every Config field
// ==========================================

func TestConfig_DefaultValues(t *testing.T) {
	cfg := manager.DefaultConfig()
	if cfg.ScriptPath != "scripts/log.js" {
		t.Errorf("default script: got '%s'", cfg.ScriptPath)
	}
	if cfg.TunnelPortRange != "8000-8010" {
		t.Errorf("default tunnel range: got '%s'", cfg.TunnelPortRange)
	}
}

func TestConfig_AllFieldsSetable(t *testing.T) {
	cfg := &manager.Config{
		PcapPath:         "/tmp/test.pcap",
		ScriptPath:       "custom/script.js",
		TCPAddr:          "127.0.0.1:8080",
		TCPTarget:        "10.0.0.1:80",
		TLSAddr:          "127.0.0.1:8443",
		TLSTarget:        "10.0.0.1:443",
		FilterExpr:       "host 1.2.3.4",
		MirrorAddr:       "192.168.1.100:5000",
		Verbose:          true,
		SniffAll:         true,
		Transparent:      true,
		Domains:          "example.com,test.com",
		AppPath:          "notepad.exe",
		IfaceAddr:        "192.168.1.1",
		ForceHTTP11:      true,
		WinDivert:        true,
		DNSSpoof:         true,
		Discovery:        true,
		HappyEyeballs:    true,
		RawSniff:         true,
		DomainToIPLink:   true,
		MITMAll:          true,
		TunnelServerAddr: ":9090",
		TunnelPortRange:  "10000-20000",
		TunnelUser:       "admin",
		TunnelPass:       "secretpass",
		TunnelClientTo:   "1.2.3.4:9090:admin:pass:8000:tcp",
	}

	if cfg.PcapPath != "/tmp/test.pcap" {
		t.Error("PcapPath")
	}
	if cfg.ScriptPath != "custom/script.js" {
		t.Error("ScriptPath")
	}
	if cfg.TCPAddr != "127.0.0.1:8080" {
		t.Error("TCPAddr")
	}
	if cfg.TCPTarget != "10.0.0.1:80" {
		t.Error("TCPTarget")
	}
	if cfg.TLSAddr != "127.0.0.1:8443" {
		t.Error("TLSAddr")
	}
	if cfg.TLSTarget != "10.0.0.1:443" {
		t.Error("TLSTarget")
	}
	if cfg.FilterExpr != "host 1.2.3.4" {
		t.Error("FilterExpr")
	}
	if cfg.MirrorAddr != "192.168.1.100:5000" {
		t.Error("MirrorAddr")
	}
	if !cfg.Verbose {
		t.Error("Verbose")
	}
	if !cfg.SniffAll {
		t.Error("SniffAll")
	}
	if !cfg.Transparent {
		t.Error("Transparent")
	}
	if cfg.Domains != "example.com,test.com" {
		t.Error("Domains")
	}
	if cfg.AppPath != "notepad.exe" {
		t.Error("AppPath")
	}
	if cfg.IfaceAddr != "192.168.1.1" {
		t.Error("IfaceAddr")
	}
	if !cfg.ForceHTTP11 {
		t.Error("ForceHTTP11")
	}
	if !cfg.WinDivert {
		t.Error("WinDivert")
	}
	if !cfg.DNSSpoof {
		t.Error("DNSSpoof")
	}
	if !cfg.Discovery {
		t.Error("Discovery")
	}
	if !cfg.HappyEyeballs {
		t.Error("HappyEyeballs")
	}
	if !cfg.RawSniff {
		t.Error("RawSniff")
	}
	if !cfg.DomainToIPLink {
		t.Error("DomainToIPLink")
	}
	if !cfg.MITMAll {
		t.Error("MITMAll")
	}
	if cfg.TunnelServerAddr != ":9090" {
		t.Error("TunnelServerAddr")
	}
	if cfg.TunnelPortRange != "10000-20000" {
		t.Error("TunnelPortRange")
	}
	if cfg.TunnelUser != "admin" {
		t.Error("TunnelUser")
	}
	if cfg.TunnelPass != "secretpass" {
		t.Error("TunnelPass")
	}
	if cfg.TunnelClientTo != "1.2.3.4:9090:admin:pass:8000:tcp" {
		t.Error("TunnelClientTo")
	}
}

func TestConfig_ShouldMITM_Callback(t *testing.T) {
	cfg := manager.DefaultConfig()
	called := false
	cfg.ShouldMITM = func(hostname string) bool {
		called = true
		return hostname == "target.com"
	}
	if !cfg.ShouldMITM("target.com") {
		t.Error("should return true")
	}
	if cfg.ShouldMITM("other.com") {
		t.Error("should return false")
	}
	if !called {
		t.Error("callback not called")
	}
}

func TestConfig_StrictInterceptDomains(t *testing.T) {
	cfg := manager.DefaultConfig()
	cfg.StrictInterceptDomains = []string{"api.example.com", "login.example.com"}
	if len(cfg.StrictInterceptDomains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(cfg.StrictInterceptDomains))
	}
}

// ==========================================
// 2. Engine — packet lifecycle
// ==========================================

func TestEngine_CreateAndStart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: engine requires admin")
	}
	t.Skip("skipping: engine starts server workers that require admin privileges")
}

func TestEngine_Process_Sync(t *testing.T) {
	t.Skip("skipping: engine requires admin privileges to start")
}

func TestEngine_GetIPType(t *testing.T) {
	tests := map[string]string{
		"127.0.0.1":   "localhost",
		"192.168.1.1": "private",
		"10.0.0.1":    "private",
		"8.8.8.8":     "public",
		"invalid":     "unknown",
	}
	for ip, expected := range tests {
		if got := engine.GetIPType(ip); got != expected {
			t.Errorf("GetIPType(%s) = %s, want %s", ip, got, expected)
		}
	}
}

// ==========================================
// 3. Manager lifecycle
// ==========================================

func TestManager_NewManager(t *testing.T) {
	cfg := manager.DefaultConfig()
	m := manager.NewManager(cfg)
	if m == nil {
		t.Fatal("manager should not be nil")
	}
}

func TestManager_Setup_MinimalConfig(t *testing.T) {
	t.Skip("skipping: manager setup requires admin privileges")
}

// ==========================================
// 4. Scope Guard — feature activation QA
// ==========================================

func TestQA_ScopeActivation_ClientMode(t *testing.T) {
	log := &testLog{}
	sm := security.NewScopeManager(security.RoleClient)

	clientFeatures := []string{"proxy_http", "proxy_socks5", "interceptor", "capture", "adblock", "dns_spoof", "stealth"}
	for _, f := range clientFeatures {
		if err := sm.ActivateFeature(f); err != nil {
			t.Errorf("client feature '%s' should activate: %v", f, err)
		}
		log.Log(fmt.Sprintf("✅ Activated: %s", f))
	}

	serverFeatures := []string{"tunnel_server", "transfer_server", "ipsec"}
	for _, f := range serverFeatures {
		if err := sm.Guard(f); err == nil {
			t.Errorf("server feature '%s' should be BLOCKED for client", f)
		}
		log.Log(fmt.Sprintf("❌ Blocked: %s (expected)", f))
	}
	log.Dump(t)
}

func TestQA_ScopeActivation_ServerMode(t *testing.T) {
	sm := security.NewScopeManager(security.RoleServer)
	if err := sm.ActivateFeature("tunnel_server"); err != nil {
		t.Errorf("tunnel_server should activate: %v", err)
	}
	if err := sm.ActivateFeature("ipsec"); err != nil {
		t.Errorf("ipsec should activate: %v", err)
	}
	for _, f := range []string{"proxy_http", "interceptor", "capture", "adblock", "stealth"} {
		if !sm.IsNotArea(f) {
			t.Errorf("'%s' should be blocked for server", f)
		}
	}
}

// ==========================================
// 6. Protocol Stack
// ==========================================

func TestStack_IPv4(t *testing.T) {
	hdr := stack.IPv4Header{Version: 4, IHL: 5, TTL: 64, Protocol: 6, Src: net.IPv4(192, 168, 1, 100), Dst: net.IPv4(10, 0, 0, 1)}
	data := hdr.Serialize()
	if len(data) != 20 {
		t.Errorf("expected 20 bytes, got %d", len(data))
	}
}

func TestStack_TCP(t *testing.T) {
	tcp := stack.TCPHeader{SrcPort: 12345, DstPort: 80, Seq: 100, Flags: 0x02, Window: 65535}
	data := tcp.Serialize(net.IPv4(192, 168, 1, 1), net.IPv4(10, 0, 0, 1), nil)
	if len(data) < 20 {
		t.Error("TCP header too short")
	}
}

func TestStack_UDP(t *testing.T) {
	udp := stack.UDPHeader{SrcPort: 53, DstPort: 53}
	data := udp.Serialize(net.IPv4(8, 8, 8, 8), net.IPv4(192, 168, 1, 1), []byte{0x01, 0x02, 0x03})
	if len(data) < 8 {
		t.Error("UDP header too short")
	}
}

// ==========================================
// 7. DTLS + DNS
// ==========================================

func TestDTLS_Detect(t *testing.T) {
	// Must be at least 13 bytes for record header
	if !dtls.IsDTLSPacket([]byte{22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Error("should detect DTLS")
	}
	if dtls.IsDTLSPacket([]byte{23, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Error("should not detect non-DTLS")
	}
}

// ==========================================
// 8. Proxy SOCKS5
// ==========================================

func TestProxy_SOCKS5_UDPRoundtrip(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 8080}
	header := proxy.BuildSOCKS5UDPHeader(addr)
	fullPacket := append(header, []byte("test payload")...)
	parsed, payload, err := proxy.ParseSOCKS5UDPHeader(fullPacket)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.DstPort != 8080 {
		t.Errorf("port: %d", parsed.DstPort)
	}
	if string(payload) != "test payload" {
		t.Error("payload")
	}
}

// ==========================================
// 9. Memory
// ==========================================

func TestMem_Reducer(t *testing.T) {
	r := mem.New()
	r.Reduce()
	ctx, cancel := context.WithCancel(context.Background())
	r.StartPeriodic(ctx, 100*time.Millisecond)
	time.Sleep(350 * time.Millisecond)
	cancel()
}

// ==========================================
// 10. Security Full Stack
// ==========================================

func TestSecurity_BruteforceAndFirewall(t *testing.T) {
	log := &testLog{}

	bl := security.NewBruteforceLimiter(3, time.Minute, 5*time.Second)
	log.Log("Bruteforce limiter created")

	fw := security.NewFirewall()
	fw.AddRule(security.FirewallRule{Name: "block-ext", Priority: 1, Action: security.FirewallDeny, DstIP: "0.0.0.0/0", Direction: security.DirectionBoth, Enabled: true})
	fw.AddRule(security.FirewallRule{Name: "allow-local", Priority: 0, Action: security.FirewallAllow, DstIP: "192.168.0.0/16", Direction: security.DirectionBoth, Enabled: true})
	log.Log("Firewall: 2 rules")

	ip := "203.0.113.50"
	for i := 0; i < 3; i++ {
		bl.RecordFailure(ip)
	}
	if bl.IsAllowed(ip) {
		t.Error("should be banned")
	}

	if fw.Evaluate("1.2.3.4", 0, "192.168.1.1", 80, "tcp", security.DirectionInbound) != security.FirewallAllow {
		t.Error("local should be allowed")
	}
	if fw.Evaluate("1.2.3.4", 0, "8.8.8.8", 53, "udp", security.DirectionOutbound) != security.FirewallDeny {
		t.Error("external should be denied")
	}
	log.Dump(t)
}

// ==========================================
// 11. QA Report
// ==========================================

func TestQA_Report(t *testing.T) {
	sm := security.NewScopeManager(security.RoleBoth)
	features := sm.ListFeatures()
	allowed := sm.ListAllowedFeatures()
	denied := sm.ListDeniedFeatures()

	t.Logf("=== QA REPORT === Total: %d | Allowed(Both): %d | Denied(Both): %d", len(features), len(allowed), len(denied))
	if len(denied) != 0 {
		t.Errorf("RoleBoth should have 0 denied, got %d", len(denied))
	}

	// Verify all features have required metadata
	for _, f := range features {
		if f.Name == "" {
			t.Errorf("feature missing name")
		}
		if f.Package == "" {
			t.Errorf("feature '%s' missing package", f.Name)
		}
		if len(f.Functions) == 0 {
			t.Errorf("feature '%s' missing functions", f.Name)
		}
	}
}
