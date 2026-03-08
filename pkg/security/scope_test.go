package security

import (
	"testing"
	"time"
)

// ==========================================
// Scope Manager Tests
// ==========================================

func TestNewScopeManager(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	if sm == nil {
		t.Fatal("should not be nil")
	}
	if sm.GetRole() != RoleClient {
		t.Errorf("expected RoleClient, got %v", sm.GetRole())
	}
}

func TestScopeManager_SetRole(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.SetRole(RoleServer)
	if sm.GetRole() != RoleServer {
		t.Error("should be RoleServer")
	}
}

func TestScopeManager_RoleBoth(t *testing.T) {
	sm := NewScopeManager(RoleBoth)
	if sm.GetRole() != RoleBoth {
		t.Error("should be RoleBoth")
	}
}

func TestRole_String(t *testing.T) {
	if RoleClient.String() != "Client" {
		t.Error("Client string mismatch")
	}
	if RoleServer.String() != "Server" {
		t.Error("Server string mismatch")
	}
	if RoleBoth.String() != "Both" {
		t.Error("Both string mismatch")
	}
}

func TestScopeDuration_String(t *testing.T) {
	if ScopeAbsolute.String() != "Absolute" {
		t.Error("Absolute string mismatch")
	}
	if ScopeTemporary.String() != "Temporary" {
		t.Error("Temporary string mismatch")
	}
}

// --- Feature Scope Tests ---

func TestFeatureScope_AllowedForRole(t *testing.T) {
	tests := []struct {
		scope   FeatureScope
		role    Role
		allowed bool
	}{
		{FeatureScopeClientOnly, RoleClient, true},
		{FeatureScopeClientOnly, RoleServer, false},
		{FeatureScopeClientOnly, RoleBoth, true},
		{FeatureScopeServerOnly, RoleClient, false},
		{FeatureScopeServerOnly, RoleServer, true},
		{FeatureScopeServerOnly, RoleBoth, true},
		{FeatureScopeBoth, RoleClient, true},
		{FeatureScopeBoth, RoleServer, true},
		{FeatureScopeBoth, RoleBoth, true},
	}
	for _, tc := range tests {
		result := tc.scope.AllowedForRole(tc.role)
		if result != tc.allowed {
			t.Errorf("FeatureScope(%s).AllowedForRole(%s) = %v, want %v",
				tc.scope, tc.role, result, tc.allowed)
		}
	}
}

// --- Client Scope: Client-Only Features ---

func TestClientScope_ProxyAllowed(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	if !sm.IsFeatureAllowed("proxy_http") {
		t.Error("proxy_http should be allowed for Client")
	}
	if !sm.IsFeatureAllowed("proxy_socks5") {
		t.Error("proxy_socks5 should be allowed for Client")
	}
}

func TestClientScope_InterceptorAllowed(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	if !sm.IsFeatureAllowed("interceptor") {
		t.Error("interceptor should be allowed for Client")
	}
	if !sm.IsFeatureAllowed("capture") {
		t.Error("capture should be allowed for Client")
	}
}

func TestClientScope_ServerFeaturesDenied(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	if sm.IsFeatureAllowed("tunnel_server") {
		t.Error("tunnel_server should NOT be allowed for Client")
	}
	if sm.IsFeatureAllowed("transfer_server") {
		t.Error("transfer_server should NOT be allowed for Client")
	}
	if sm.IsFeatureAllowed("ipsec") {
		t.Error("ipsec should NOT be allowed for Client")
	}
}

// --- Server Scope: Server-Only Features ---

func TestServerScope_TunnelServerAllowed(t *testing.T) {
	sm := NewScopeManager(RoleServer)
	if !sm.IsFeatureAllowed("tunnel_server") {
		t.Error("tunnel_server should be allowed for Server")
	}
	if !sm.IsFeatureAllowed("transfer_server") {
		t.Error("transfer_server should be allowed for Server")
	}
	if !sm.IsFeatureAllowed("ipsec") {
		t.Error("ipsec should be allowed for Server")
	}
}

func TestServerScope_ClientFeaturesDenied(t *testing.T) {
	sm := NewScopeManager(RoleServer)
	if sm.IsFeatureAllowed("proxy_http") {
		t.Error("proxy_http should NOT be allowed for Server")
	}
	if sm.IsFeatureAllowed("interceptor") {
		t.Error("interceptor should NOT be allowed for Server")
	}
	if sm.IsFeatureAllowed("adblock") {
		t.Error("adblock should NOT be allowed for Server")
	}
	if sm.IsFeatureAllowed("dns_spoof") {
		t.Error("dns_spoof should NOT be allowed for Server")
	}
	if sm.IsFeatureAllowed("stealth") {
		t.Error("stealth should NOT be allowed for Server")
	}
}

// --- Both Role: All Features ---

func TestBothRole_AllFeaturesAllowed(t *testing.T) {
	sm := NewScopeManager(RoleBoth)
	features := sm.ListFeatures()
	for _, f := range features {
		if !sm.IsFeatureAllowed(f.Name) {
			t.Errorf("feature '%s' should be allowed for RoleBoth", f.Name)
		}
	}
}

// --- Shared Features ---

func TestSharedFeatures_AllRoles(t *testing.T) {
	sharedFeatures := []string{"engine", "firewall", "bruteforce", "mem_reducer", "perf", "dtls", "tls", "cgnat"}
	for _, role := range []Role{RoleClient, RoleServer, RoleBoth} {
		sm := NewScopeManager(role)
		for _, f := range sharedFeatures {
			if !sm.IsFeatureAllowed(f) {
				t.Errorf("feature '%s' should be allowed for %s", f, role)
			}
		}
	}
}

// --- Absolute vs Temporary Scope ---

func TestAbsoluteScope(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.SetAbsoluteScope(ScopePrivateOnly)
	if sm.GetActiveScope() != ScopePrivateOnly {
		t.Error("absolute scope should be PrivateOnly")
	}
}

func TestTemporaryScope_Overrides(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.SetAbsoluteScope(ScopePrivateOnly)
	sm.SetTemporaryScope(ScopeAll, 5*time.Second, "testing")

	if sm.GetActiveScope() != ScopeAll {
		t.Error("temporary scope should override absolute")
	}
	if !sm.HasTemporaryScope() {
		t.Error("should have temporary scope")
	}
}

func TestTemporaryScope_Expires(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.SetAbsoluteScope(ScopePrivateOnly)
	sm.SetTemporaryScope(ScopeAll, 100*time.Millisecond, "short-lived")

	time.Sleep(200 * time.Millisecond)

	if sm.GetActiveScope() != ScopePrivateOnly {
		t.Error("expired temporary scope should revert to absolute")
	}
	if sm.HasTemporaryScope() {
		t.Error("temporary scope should have expired")
	}
}

func TestTemporaryScope_Clear(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.SetTemporaryScope(ScopePublicOnly, time.Hour, "test")
	sm.ClearTemporaryScope()

	if sm.HasTemporaryScope() {
		t.Error("temporary scope should be cleared")
	}
}

func TestTemporaryScope_GetEntry(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.SetTemporaryScope(ScopeAll, 5*time.Second, "debug session")

	entry := sm.GetTemporaryScope()
	if entry == nil {
		t.Fatal("should return entry")
	}
	if entry.Reason != "debug session" {
		t.Errorf("expected reason 'debug session', got '%s'", entry.Reason)
	}
}

// --- Feature Registry ---

func TestFeatureRegistry_Count(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	features := sm.ListFeatures()
	if len(features) < 20 {
		t.Errorf("expected at least 20 registered features, got %d", len(features))
	}
}

func TestFeatureRegistry_GetFeature(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	f := sm.GetFeature("proxy_http")
	if f == nil {
		t.Fatal("proxy_http should exist")
	}
	if f.Package != "pkg/proxy" {
		t.Errorf("expected package 'pkg/proxy', got '%s'", f.Package)
	}
	if len(f.Functions) == 0 {
		t.Error("should have functions listed")
	}
}

func TestFeatureRegistry_NonExistent(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	if sm.IsFeatureAllowed("nonexistent") {
		t.Error("non-existent feature should not be allowed")
	}
}

func TestFeatureRegistry_CustomFeature(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.RegisterFeature(&Feature{
		Name:        "custom_plugin",
		Package:     "pkg/plugins",
		Description: "User custom plugin",
		Scope:       FeatureScopeClientOnly,
		Functions:   []string{"Init", "Run"},
	})
	if !sm.IsFeatureAllowed("custom_plugin") {
		t.Error("custom plugin should be allowed for Client")
	}
}

// --- Allowed/Denied Lists ---

func TestListAllowedFeatures_Client(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	allowed := sm.ListAllowedFeatures()
	denied := sm.ListDeniedFeatures()

	if len(allowed) == 0 {
		t.Error("client should have allowed features")
	}
	if len(denied) == 0 {
		t.Error("client should have denied features (server-only)")
	}
	// Server-only features should be in denied
	for _, f := range denied {
		if f.Scope == FeatureScopeClientOnly || f.Scope == FeatureScopeBoth {
			t.Errorf("feature '%s' (scope=%s) should NOT be in denied list for Client", f.Name, f.Scope)
		}
	}
}

func TestListAllowedFeatures_Server(t *testing.T) {
	sm := NewScopeManager(RoleServer)
	denied := sm.ListDeniedFeatures()
	for _, f := range denied {
		if f.Scope == FeatureScopeServerOnly || f.Scope == FeatureScopeBoth {
			t.Errorf("feature '%s' (scope=%s) should NOT be in denied list for Server", f.Name, f.Scope)
		}
	}
}

// --- History ---

func TestScopeHistory(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.SetRole(RoleServer)
	sm.SetAbsoluteScope(ScopePrivateOnly)
	sm.SetTemporaryScope(ScopeAll, time.Second, "test")

	history := sm.GetHistory()
	if len(history) != 3 {
		t.Errorf("expected 3 history entries, got %d", len(history))
	}
}

// --- Feature Functions ---

func TestFeature_HasFunctions(t *testing.T) {
	sm := NewScopeManager(RoleBoth)
	features := sm.ListFeatures()
	for _, f := range features {
		if len(f.Functions) == 0 {
			t.Errorf("feature '%s' should have functions listed", f.Name)
		}
	}
}

func TestFeature_HasPackage(t *testing.T) {
	sm := NewScopeManager(RoleBoth)
	features := sm.ListFeatures()
	for _, f := range features {
		if f.Package == "" {
			t.Errorf("feature '%s' should have package listed", f.Name)
		}
	}
}

// ==========================================
// Runtime Enforcement Guard Tests
// ==========================================

// --- Guard: Role-based blocking ---

func TestGuard_ServerBlockedForClient(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	err := sm.Guard("tunnel_server")
	if err == nil {
		t.Error("tunnel_server should be BLOCKED for Client role")
	}
}

func TestGuard_ClientAllowedForClient(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	err := sm.Guard("proxy_http")
	if err != nil {
		t.Errorf("proxy_http should be allowed for Client: %v", err)
	}
}

func TestGuard_UnknownFeature(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	err := sm.Guard("nonexistent_feature")
	if err == nil {
		t.Error("unknown feature should be blocked")
	}
}

// --- IsNotArea: Convenience check ---

func TestIsNotArea_ServerFeatureNotInClientArea(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	if !sm.IsNotArea("tunnel_server") {
		t.Error("tunnel_server IS NOT AREA for Client")
	}
	if !sm.IsNotArea("ipsec") {
		t.Error("ipsec IS NOT AREA for Client")
	}
}

func TestIsNotArea_ClientFeatureInClientArea(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	if sm.IsNotArea("proxy_http") {
		t.Error("proxy_http IS in area for Client")
	}
}

func TestIsNotAreaFor_SpecificRole(t *testing.T) {
	sm := NewScopeManager(RoleBoth) // current role doesn't matter
	if !sm.IsNotAreaFor("interceptor", RoleServer) {
		t.Error("interceptor IS NOT AREA for Server role")
	}
	if sm.IsNotAreaFor("interceptor", RoleClient) {
		t.Error("interceptor IS in area for Client role")
	}
}

// --- Cross-Feature Conflict: Transfer blocks MITM/sniff ---

func TestTransferConflictsWithInterceptor(t *testing.T) {
	sm := NewScopeManager(RoleClient) // Client can use both transfer and interceptor normally
	// Activate transfer_client
	err := sm.ActivateFeature("transfer_client")
	if err != nil {
		t.Fatalf("activating transfer_client should succeed: %v", err)
	}
	// Now try to activate interceptor — should be BLOCKED
	err = sm.Guard("interceptor")
	if err == nil {
		t.Error("interceptor should be BLOCKED while transfer_client is active")
	}
}

func TestTransferConflictsWithCapture(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.ActivateFeature("transfer_client")

	err := sm.Guard("capture")
	if err == nil {
		t.Error("capture (sniff) should be BLOCKED while transfer_client is active")
	}
}

func TestTransferConflictsWithProxy(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.ActivateFeature("transfer_client")

	if !sm.IsNotArea("proxy_http") {
		t.Error("proxy_http should NOT be accessible during transfer")
	}
	if !sm.IsNotArea("proxy_socks5") {
		t.Error("proxy_socks5 should NOT be accessible during transfer")
	}
}

func TestTransferConflictsWithDnsSpoof(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.ActivateFeature("transfer_client")

	if !sm.IsNotArea("dns_spoof") {
		t.Error("dns_spoof should NOT be accessible during transfer")
	}
}

// --- Reverse: interceptor active blocks transfer ---

func TestInterceptorActiveBlocksTransfer(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.ActivateFeature("interceptor")

	err := sm.Guard("transfer_client")
	if err == nil {
		t.Error("transfer_client should be BLOCKED while interceptor is active (bidirectional conflict)")
	}
}

// --- Deactivate: after deactivation, conflict clears ---

func TestDeactivateFeature_ClearsConflict(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.ActivateFeature("transfer_client")

	// Interceptor blocked
	if !sm.IsNotArea("interceptor") {
		t.Error("interceptor should be blocked during transfer")
	}

	// Deactivate transfer
	sm.DeactivateFeature("transfer_client")

	// Now interceptor should be allowed again
	if sm.IsNotArea("interceptor") {
		t.Error("interceptor should be allowed after transfer deactivated")
	}
}

// --- Active Features tracking ---

func TestGetActiveFeatures(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.ActivateFeature("proxy_http")
	sm.ActivateFeature("adblock")

	active := sm.GetActiveFeatures()
	if len(active) != 2 {
		t.Errorf("expected 2 active features, got %d", len(active))
	}
}

// --- Violation tracking ---

func TestViolationLogged(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.Guard("tunnel_server") // will fail — server-only for client

	violations := sm.GetViolations()
	if len(violations) == 0 {
		t.Error("violation should be logged")
	}
	if violations[0].Feature != "tunnel_server" {
		t.Errorf("violation feature should be 'tunnel_server', got '%s'", violations[0].Feature)
	}
}

func TestViolationLoggedOnConflict(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.ActivateFeature("transfer_client")
	sm.Guard("interceptor") // will fail — conflict

	violations := sm.GetViolations()
	found := false
	for _, v := range violations {
		if v.Feature == "interceptor" {
			found = true
			break
		}
	}
	if !found {
		t.Error("conflict violation should be logged for interceptor")
	}
}

func TestClearViolations(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	sm.Guard("tunnel_server")
	sm.ClearViolations()

	if len(sm.GetViolations()) != 0 {
		t.Error("violations should be cleared")
	}
}

// --- MustGuard panics ---

func TestMustGuard_Panics(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	defer func() {
		r := recover()
		if r == nil {
			t.Error("MustGuard should panic on blocked feature")
		}
	}()
	sm.MustGuard("tunnel_server")
}

func TestMustGuard_NoPanic(t *testing.T) {
	sm := NewScopeManager(RoleClient)
	// Should NOT panic
	sm.MustGuard("proxy_http")
}

// --- Tunnel server conflicts ---

func TestTunnelServerConflictsWithCapture(t *testing.T) {
	sm := NewScopeManager(RoleServer)
	sm.ActivateFeature("tunnel_server")

	// capture is client-only, so blocked by role AND conflict
	if !sm.IsNotArea("capture") {
		t.Error("capture should be blocked for server with tunnel_server active")
	}
}
