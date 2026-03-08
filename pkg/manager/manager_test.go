package manager

import (
	"net"
	"testing"
)

// --- DefaultConfig ---

func TestDefaultConfig_ScriptPath(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ScriptPath != "scripts/log.js" {
		t.Errorf("Expected ScriptPath 'scripts/log.js', got '%s'", cfg.ScriptPath)
	}
}

func TestDefaultConfig_TunnelPortRange(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.TunnelPortRange != "8000-8010" {
		t.Errorf("Expected TunnelPortRange '8000-8010', got '%s'", cfg.TunnelPortRange)
	}
}

func TestDefaultConfig_NotNil(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig should return non-nil config")
	}
}

func TestDefaultConfig_EmptyPaths(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.PcapPath != "" {
		t.Errorf("PcapPath should be empty by default, got '%s'", cfg.PcapPath)
	}
	if cfg.TCPAddr != "" {
		t.Errorf("TCPAddr should be empty by default, got '%s'", cfg.TCPAddr)
	}
	if cfg.TLSAddr != "" {
		t.Errorf("TLSAddr should be empty by default, got '%s'", cfg.TLSAddr)
	}
	if cfg.FilterExpr != "" {
		t.Errorf("FilterExpr should be empty by default, got '%s'", cfg.FilterExpr)
	}
	if cfg.MirrorAddr != "" {
		t.Errorf("MirrorAddr should be empty by default, got '%s'", cfg.MirrorAddr)
	}
	if cfg.AppPath != "" {
		t.Errorf("AppPath should be empty by default, got '%s'", cfg.AppPath)
	}
}

func TestDefaultConfig_BoolDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.SniffAll {
		t.Error("SniffAll should be false by default")
	}
	if cfg.Transparent {
		t.Error("Transparent should be false by default")
	}
	if cfg.Verbose {
		t.Error("Verbose should be false by default")
	}
	if cfg.MITMAll {
		t.Error("MITMAll should be false by default")
	}
	if cfg.WinDivert {
		t.Error("WinDivert should be false by default")
	}
	if cfg.DNSSpoof {
		t.Error("DNSSpoof should be false by default")
	}
	if cfg.Discovery {
		t.Error("Discovery should be false by default")
	}
	if cfg.HappyEyeballs {
		t.Error("HappyEyeballs should be false by default")
	}
	if cfg.RawSniff {
		t.Error("RawSniff should be false by default")
	}
	if cfg.DomainToIPLink {
		t.Error("DomainToIPLink should be false by default")
	}
	if cfg.ForceHTTP11 {
		t.Error("ForceHTTP11 should be false by default")
	}
}

// --- NewManager ---

func TestNewManager_NilConfig(t *testing.T) {
	m := NewManager(nil)
	if m == nil {
		t.Fatal("NewManager should return non-nil manager")
	}
	if m.Config == nil {
		t.Fatal("Config should not be nil when passing nil (uses defaults)")
	}
	if m.Config.ScriptPath != "scripts/log.js" {
		t.Errorf("Expected default ScriptPath, got '%s'", m.Config.ScriptPath)
	}
}

func TestNewManager_WithConfig(t *testing.T) {
	cfg := &Config{
		ScriptPath: "custom/script.js",
		Verbose:    true,
		MITMAll:    true,
	}
	m := NewManager(cfg)
	if m.Config.ScriptPath != "custom/script.js" {
		t.Errorf("Expected custom ScriptPath, got '%s'", m.Config.ScriptPath)
	}
	if !m.Config.Verbose {
		t.Error("Verbose should be true")
	}
	if !m.Config.MITMAll {
		t.Error("MITMAll should be true")
	}
}

func TestNewManager_EngineInitialized(t *testing.T) {
	m := NewManager(nil)
	if m.Engine == nil {
		t.Fatal("Engine should be initialized by NewManager")
	}
}

func TestNewManager_SubComponentsNil(t *testing.T) {
	m := NewManager(nil)
	if m.Runtime != nil {
		t.Error("Runtime should be nil before Setup")
	}
	if m.Sniffer != nil {
		t.Error("Sniffer should be nil before Setup")
	}
	if m.HostsMgr != nil {
		t.Error("HostsMgr should be nil before Setup")
	}
	if m.RootCA != nil {
		t.Error("RootCA should be nil before Setup")
	}
}

// --- getLocalIPs ---

func TestGetLocalIPs_NotEmpty(t *testing.T) {
	ips := getLocalIPs()
	if len(ips) == 0 {
		t.Error("getLocalIPs should return at least one IP on any machine")
	}
}

func TestGetLocalIPs_ValidIPs(t *testing.T) {
	ips := getLocalIPs()
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Errorf("getLocalIPs returned invalid IP: '%s'", ip)
		}
	}
}

func TestGetLocalIPs_ContainsLoopback(t *testing.T) {
	ips := getLocalIPs()
	hasLoopback := false
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.IsLoopback() {
			hasLoopback = true
			break
		}
	}
	if !hasLoopback {
		t.Log("Note: getLocalIPs did not return a loopback address (may depend on OS)")
	}
}
