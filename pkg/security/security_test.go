package security

import (
	"testing"
	"time"
)

func TestNewBruteforceLimiter(t *testing.T) {
	bl := NewBruteforceLimiter(5, time.Minute, 10*time.Minute)
	if bl == nil {
		t.Fatal("should not be nil")
	}
}

func TestBruteforceLimiter_AllowedByDefault(t *testing.T) {
	bl := NewBruteforceLimiter(3, time.Minute, time.Minute)
	if !bl.IsAllowed("192.168.1.100") {
		t.Error("new IP should be allowed")
	}
}

func TestBruteforceLimiter_BanAfterMaxAttempts(t *testing.T) {
	bl := NewBruteforceLimiter(3, time.Minute, time.Minute)
	ip := "10.0.0.1"

	bl.RecordFailure(ip)
	bl.RecordFailure(ip)
	banned := bl.RecordFailure(ip) // 3rd failure

	if !banned {
		t.Error("should be banned after 3 failures")
	}
	if bl.IsAllowed(ip) {
		t.Error("banned IP should not be allowed")
	}
}

func TestBruteforceLimiter_SuccessClears(t *testing.T) {
	bl := NewBruteforceLimiter(3, time.Minute, time.Minute)
	ip := "10.0.0.2"

	bl.RecordFailure(ip)
	bl.RecordFailure(ip)
	bl.RecordSuccess(ip) // Clear

	if !bl.IsAllowed(ip) {
		t.Error("successful auth should clear failures")
	}
}

func TestBruteforceLimiter_UnbanIP(t *testing.T) {
	bl := NewBruteforceLimiter(2, time.Minute, 10*time.Minute)
	ip := "172.16.0.1"

	bl.RecordFailure(ip)
	bl.RecordFailure(ip)

	bl.UnbanIP(ip)
	if !bl.IsAllowed(ip) {
		t.Error("unbanned IP should be allowed")
	}
}

func TestBruteforceLimiter_GetBannedIPs(t *testing.T) {
	bl := NewBruteforceLimiter(1, time.Minute, 10*time.Minute)

	bl.RecordFailure("1.1.1.1")
	bl.RecordFailure("2.2.2.2")

	banned := bl.GetBannedIPs()
	if len(banned) != 2 {
		t.Errorf("expected 2 banned IPs, got %d", len(banned))
	}
}

func TestBruteforceLimiter_DifferentIPs(t *testing.T) {
	bl := NewBruteforceLimiter(3, time.Minute, time.Minute)

	bl.RecordFailure("10.0.0.1")
	bl.RecordFailure("10.0.0.1")
	// 10.0.0.1 has 2 failures

	if !bl.IsAllowed("10.0.0.2") {
		t.Error("different IP should not be affected")
	}
}

// ==========================================
// Firewall Tests (#18)
// ==========================================

func TestNewFirewall(t *testing.T) {
	fw := NewFirewall()
	if fw == nil {
		t.Fatal("should not be nil")
	}
}

func TestFirewall_DefaultAllow(t *testing.T) {
	fw := NewFirewall()
	action := fw.Evaluate("1.2.3.4", 12345, "5.6.7.8", 80, "tcp", DirectionOutbound)
	if action != FirewallAllow {
		t.Error("default should be ALLOW")
	}
}

func TestFirewall_DenyRule(t *testing.T) {
	fw := NewFirewall()
	fw.AddRule(FirewallRule{
		Name:      "block-80",
		Priority:  1,
		Action:    FirewallDeny,
		Direction: DirectionBoth,
		DstPort:   80,
		Protocol:  "tcp",
		Enabled:   true,
	})

	action := fw.Evaluate("1.2.3.4", 50000, "5.6.7.8", 80, "tcp", DirectionOutbound)
	if action != FirewallDeny {
		t.Error("should deny traffic to port 80")
	}
}

func TestFirewall_AllowOverride(t *testing.T) {
	fw := NewFirewall()
	fw.AddRule(FirewallRule{
		Name:      "deny-all",
		Priority:  10,
		Action:    FirewallDeny,
		Direction: DirectionBoth,
		Enabled:   true,
	})
	fw.AddRule(FirewallRule{
		Name:      "allow-dns",
		Priority:  1, // Higher priority (lower number)
		Action:    FirewallAllow,
		Direction: DirectionOutbound,
		DstPort:   53,
		Enabled:   true,
	})

	// DNS should be allowed (higher priority)
	action := fw.Evaluate("10.0.0.1", 5000, "8.8.8.8", 53, "udp", DirectionOutbound)
	if action != FirewallAllow {
		t.Error("DNS should be allowed by higher-priority rule")
	}
}

func TestFirewall_CIDRMatch(t *testing.T) {
	fw := NewFirewall()
	fw.AddRule(FirewallRule{
		Name:      "block-private",
		Priority:  1,
		Action:    FirewallDeny,
		Direction: DirectionOutbound,
		DstIP:     "192.168.0.0/16",
		Enabled:   true,
	})

	action := fw.Evaluate("10.0.0.1", 80, "192.168.1.100", 443, "tcp", DirectionOutbound)
	if action != FirewallDeny {
		t.Error("should deny traffic to 192.168.x.x")
	}

	action = fw.Evaluate("10.0.0.1", 80, "8.8.8.8", 53, "udp", DirectionOutbound)
	if action != FirewallAllow {
		t.Error("should allow traffic to 8.8.8.8")
	}
}

func TestFirewall_DisabledRule(t *testing.T) {
	fw := NewFirewall()
	fw.AddRule(FirewallRule{
		Name:     "disabled",
		Priority: 1,
		Action:   FirewallDeny,
		DstPort:  80,
		Enabled:  false, // Disabled
	})

	action := fw.Evaluate("1.1.1.1", 80, "2.2.2.2", 80, "tcp", DirectionOutbound)
	if action != FirewallAllow {
		t.Error("disabled rule should not match")
	}
}

func TestFirewall_RemoveRule(t *testing.T) {
	fw := NewFirewall()
	fw.AddRule(FirewallRule{Name: "test", Priority: 1, Action: FirewallDeny, DstPort: 80, Enabled: true})
	fw.RemoveRule("test")
	rules := fw.ListRules()
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after removal, got %d", len(rules))
	}
}

func TestFirewall_ListRules(t *testing.T) {
	fw := NewFirewall()
	fw.AddRule(FirewallRule{Name: "r1", Enabled: true})
	fw.AddRule(FirewallRule{Name: "r2", Enabled: true})
	rules := fw.ListRules()
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
}

// ==========================================
// Network Scope Tests (#17)
// ==========================================

func TestScopeController_PrivateOnly(t *testing.T) {
	sc := NewScopeController(ScopePrivateOnly)

	if !sc.IsAllowed("192.168.1.100") {
		t.Error("private IP should be allowed in PrivateOnly mode")
	}
	if !sc.IsAllowed("10.0.0.1") {
		t.Error("10.x should be allowed")
	}
	if sc.IsAllowed("8.8.8.8") {
		t.Error("public IP should NOT be allowed in PrivateOnly mode")
	}
	// IPv6
	if !sc.IsAllowed("::1") {
		t.Error("::1 should be allowed as private")
	}
	if !sc.IsAllowed("fe80::1") {
		t.Error("link-local should be allowed as private")
	}
	if !sc.IsAllowed("fd00::1") {
		t.Error("ULA should be allowed as private")
	}
	if sc.IsAllowed("2001:db8::1") {
		t.Error("public IPv6 should NOT be allowed as private")
	}
}

func TestScopeController_PublicOnly(t *testing.T) {
	sc := NewScopeController(ScopePublicOnly)

	if sc.IsAllowed("192.168.1.100") {
		t.Error("private IP should NOT be allowed in PublicOnly mode")
	}
	if !sc.IsAllowed("8.8.8.8") {
		t.Error("public IP should be allowed in PublicOnly mode")
	}
}

func TestScopeController_All(t *testing.T) {
	sc := NewScopeController(ScopeAll)

	if !sc.IsAllowed("192.168.1.100") {
		t.Error("private IP should be allowed in All mode")
	}
	if !sc.IsAllowed("8.8.8.8") {
		t.Error("public IP should be allowed in All mode")
	}
}

func TestScopeController_InvalidIP(t *testing.T) {
	sc := NewScopeController(ScopeAll)
	if sc.IsAllowed("not-an-ip") {
		t.Error("invalid IP should not be allowed")
	}
}

// ==========================================
// Stealth Mode Tests (#22)
// ==========================================

func TestDefaultStealthConfig(t *testing.T) {
	sc := DefaultStealthConfig()
	if !sc.Enabled {
		t.Error("stealth should be enabled by default")
	}
	if !sc.SuppressHeaders {
		t.Error("header suppression should be on")
	}
	if !sc.HideFromClient {
		t.Error("hide from client should be on")
	}
}

func TestStealthConfig_SuppressHeaders(t *testing.T) {
	sc := DefaultStealthConfig()

	suppressedHeaders := []string{
		"Via", "X-Forwarded-For", "X-Forwarded-Proto",
		"Proxy-Connection", "X-Real-IP",
	}
	for _, h := range suppressedHeaders {
		if !sc.ShouldSuppressHeader(h) {
			t.Errorf("header '%s' should be suppressed in stealth mode", h)
		}
	}

	// Non-proxy headers should NOT be suppressed
	normalHeaders := []string{"Content-Type", "Authorization", "Accept", "Host"}
	for _, h := range normalHeaders {
		if sc.ShouldSuppressHeader(h) {
			t.Errorf("header '%s' should NOT be suppressed", h)
		}
	}
}

func TestStealthConfig_Disabled(t *testing.T) {
	sc := &StealthConfig{SuppressHeaders: false}
	if sc.ShouldSuppressHeader("Via") {
		t.Error("should not suppress when disabled")
	}
}

// ==========================================
// IPsec Tests (#21)
// ==========================================

func TestIPsecAction_String(t *testing.T) {
	if IPsecActionAllow.String() != "Allow" {
		t.Error("Allow string mismatch")
	}
	if IPsecActionBlock.String() != "Block" {
		t.Error("Block string mismatch")
	}
	if IPsecActionRequireEncryption.String() != "RequireEncryption" {
		t.Error("RequireEncryption string mismatch")
	}
}

func TestNewDefaultMainModeCrypto(t *testing.T) {
	mc := NewDefaultMainModeCrypto()
	if mc.Encryption != "AES256" {
		t.Errorf("expected AES256, got '%s'", mc.Encryption)
	}
	if mc.Hash != "SHA256" {
		t.Errorf("expected SHA256, got '%s'", mc.Hash)
	}
	if mc.DHGroup != 14 {
		t.Errorf("expected DH group 14, got %d", mc.DHGroup)
	}
}

func TestNewDefaultQuickModeCrypto(t *testing.T) {
	qc := NewDefaultQuickModeCrypto()
	if qc.Encryption != "AES256-GCM" {
		t.Errorf("expected AES256-GCM, got '%s'", qc.Encryption)
	}
	if !qc.PFS {
		t.Error("PFS should be enabled by default")
	}
}

func TestNewPSKPhase1Auth(t *testing.T) {
	auth := NewPSKPhase1Auth("test-psk", "mysecretkey")
	if auth.Method != "PreSharedKey" {
		t.Error("method should be PreSharedKey")
	}
	if auth.PSK != "mysecretkey" {
		t.Error("PSK mismatch")
	}
}

func TestNewCertPhase1Auth(t *testing.T) {
	auth := NewCertPhase1Auth("test-cert", "/path/to/cert.pem")
	if auth.Method != "Certificate" {
		t.Error("method should be Certificate")
	}
	if auth.CertPath != "/path/to/cert.pem" {
		t.Error("cert path mismatch")
	}
}

func TestIPsecPolicy_Evaluate(t *testing.T) {
	policy := NewIPsecPolicy("test-policy")
	policy.AddRule(IPsecRule{
		Name:     "block-ssh",
		Action:   IPsecActionBlock,
		DstPort:  22,
		Protocol: "tcp",
		Enabled:  true,
	})
	policy.AddRule(IPsecRule{
		Name:     "encrypt-all",
		Action:   IPsecActionRequireEncryption,
		Protocol: "any",
		Enabled:  true,
	})

	// SSH should be blocked
	action := policy.Evaluate("10.0.0.1", "10.0.0.2", "tcp", 50000, 22)
	if action != IPsecActionBlock {
		t.Error("SSH should be blocked")
	}

	// Other traffic should require encryption
	action = policy.Evaluate("10.0.0.1", "10.0.0.2", "tcp", 50000, 443)
	if action != IPsecActionRequireEncryption {
		t.Error("other traffic should require encryption")
	}
}

func TestIPsecPolicy_Disabled(t *testing.T) {
	policy := NewIPsecPolicy("disabled")
	policy.Enabled = false
	policy.AddRule(IPsecRule{
		Name:    "block-all",
		Action:  IPsecActionBlock,
		Enabled: true,
	})

	action := policy.Evaluate("1.1.1.1", "2.2.2.2", "tcp", 80, 443)
	if action != IPsecActionAllow {
		t.Error("disabled policy should allow all")
	}
}

func TestFirewallAction_String(t *testing.T) {
	if FirewallAllow.String() != "ALLOW" {
		t.Error("ALLOW string mismatch")
	}
	if FirewallDeny.String() != "DENY" {
		t.Error("DENY string mismatch")
	}
	if FirewallLog.String() != "LOG" {
		t.Error("LOG string mismatch")
	}
}
