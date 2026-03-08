package security

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ==========================================
// Scope Networking: Client/Server + Absolute/Temporary
// ==========================================

// Role defines what role this NetKit instance runs as.
type Role int

const (
	RoleClient Role = iota // Client-side: interceptor, proxy, sniffer
	RoleServer             // Server-side: tunnel server, relay hub
	RoleBoth               // Both: can use all features
)

func (r Role) String() string {
	switch r {
	case RoleClient:
		return "Client"
	case RoleServer:
		return "Server"
	case RoleBoth:
		return "Both"
	default:
		return "Unknown"
	}
}

// ScopeDuration defines whether a scope setting is permanent or temporary.
type ScopeDuration int

const (
	ScopeAbsolute  ScopeDuration = iota // Permanent, persists across restarts
	ScopeTemporary                      // Reverts after TTL or session ends
)

func (d ScopeDuration) String() string {
	switch d {
	case ScopeAbsolute:
		return "Absolute"
	case ScopeTemporary:
		return "Temporary"
	default:
		return "Unknown"
	}
}

// FeatureScope defines which role can use a feature.
type FeatureScope int

const (
	FeatureScopeClientOnly FeatureScope = iota // Only available in Client role
	FeatureScopeServerOnly                     // Only available in Server role
	FeatureScopeBoth                           // Available in both roles
)

func (fs FeatureScope) String() string {
	switch fs {
	case FeatureScopeClientOnly:
		return "ClientOnly"
	case FeatureScopeServerOnly:
		return "ServerOnly"
	case FeatureScopeBoth:
		return "Both"
	default:
		return "Unknown"
	}
}

// AllowedForRole checks if this feature scope permits the given role.
func (fs FeatureScope) AllowedForRole(role Role) bool {
	switch fs {
	case FeatureScopeClientOnly:
		return role == RoleClient || role == RoleBoth
	case FeatureScopeServerOnly:
		return role == RoleServer || role == RoleBoth
	case FeatureScopeBoth:
		return true
	}
	return false
}

// Feature represents a registered feature with its scope.
type Feature struct {
	Name          string // e.g. "proxy", "tunnel_server"
	Package       string // e.g. "pkg/proxy"
	Description   string
	Scope         FeatureScope // Which role can use it
	Functions     []string     // Key exported functions
	ConflictsWith []string     // Features that CANNOT run alongside this one
}

// TemporaryScopeEntry tracks a temporary scope override.
type TemporaryScopeEntry struct {
	Role      Role
	Scope     NetworkScope
	CreatedAt time.Time
	ExpiresAt time.Time
	Reason    string
}

// ScopeViolation records a blocked feature access attempt.
type ScopeViolation struct {
	Timestamp time.Time
	Feature   string // Feature that was blocked
	Reason    string // Why it was blocked
	Caller    string // Who tried to access it (if known)
	Role      Role   // Role at the time
}

// ScopeManager manages the system-wide scope configuration.
// It controls which features are accessible based on the current Role
// and whether scope overrides are absolute or temporary.
type ScopeManager struct {
	mu sync.RWMutex

	// Current role
	currentRole Role

	// Network scope (private/public/all)
	absoluteScope  NetworkScope
	temporaryScope *TemporaryScopeEntry // nil = no temporary override

	// Feature registry
	features map[string]*Feature

	// Active features — currently running features
	activeFeatures map[string]bool

	// Scope history
	history []ScopeChangeEvent

	// Violation log — blocked access attempts
	violations []ScopeViolation
}

// ScopeChangeEvent records a scope change for audit.
type ScopeChangeEvent struct {
	Timestamp time.Time
	From      string
	To        string
	Duration  ScopeDuration
	Reason    string
}

// NewScopeManager creates a new scope manager with a given role.
func NewScopeManager(role Role) *ScopeManager {
	sm := &ScopeManager{
		currentRole:    role,
		absoluteScope:  ScopeAll,
		features:       make(map[string]*Feature),
		activeFeatures: make(map[string]bool),
		history:        make([]ScopeChangeEvent, 0),
		violations:     make([]ScopeViolation, 0),
	}
	sm.registerBuiltinFeatures()
	return sm
}

// ==========================================
// Role Management
// ==========================================

// GetRole returns the current role.
func (sm *ScopeManager) GetRole() Role {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.currentRole
}

// SetRole changes the current role (absolute).
func (sm *ScopeManager) SetRole(role Role) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	old := sm.currentRole
	sm.currentRole = role
	sm.history = append(sm.history, ScopeChangeEvent{
		Timestamp: time.Now(),
		From:      old.String(),
		To:        role.String(),
		Duration:  ScopeAbsolute,
		Reason:    "Role changed",
	})
	fmt.Printf("[Scope] 🔄 Role changed: %s → %s (Absolute)\n", old, role)
}

// ==========================================
// Network Scope (Absolute / Temporary)
// ==========================================

// GetActiveScope returns the effective network scope.
// Temporary overrides take precedence over absolute.
func (sm *ScopeManager) GetActiveScope() NetworkScope {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.temporaryScope != nil {
		if time.Now().Before(sm.temporaryScope.ExpiresAt) {
			return sm.temporaryScope.Scope
		}
		// Expired — will be cleaned up
	}
	return sm.absoluteScope
}

// IsAllowed checks if a destination IP is within the allowed network scope.
func (sm *ScopeManager) IsAllowed(ipOrHostPort string) bool {
	host, _, err := net.SplitHostPort(ipOrHostPort)
	if err != nil {
		host = ipOrHostPort // Assume it's just an IP
	}
	parsed := net.ParseIP(host)
	if parsed == nil {
		// It's a domain name. We allow it at this level, as the dialer will
		// resolve it and we can check the IP scope then if needed.
		return true
	}

	isPriv := IsPrivateIP(parsed)
	scope := sm.GetActiveScope()

	switch scope {
	case ScopePrivateOnly:
		return isPriv
	case ScopePublicOnly:
		return !isPriv
	case ScopeAll:
		return true
	}
	return false
}

// SetAbsoluteScope sets the permanent network scope.
func (sm *ScopeManager) SetAbsoluteScope(scope NetworkScope) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	old := sm.absoluteScope
	sm.absoluteScope = scope
	sm.history = append(sm.history, ScopeChangeEvent{
		Timestamp: time.Now(),
		From:      fmt.Sprintf("Scope:%d", old),
		To:        fmt.Sprintf("Scope:%d", scope),
		Duration:  ScopeAbsolute,
	})
	fmt.Printf("[Scope] 📌 Absolute scope set: %d → %d\n", old, scope)
}

// SetTemporaryScope sets a temporary scope override with a TTL.
func (sm *ScopeManager) SetTemporaryScope(scope NetworkScope, ttl time.Duration, reason string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	now := time.Now()
	sm.temporaryScope = &TemporaryScopeEntry{
		Role:      sm.currentRole,
		Scope:     scope,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Reason:    reason,
	}
	sm.history = append(sm.history, ScopeChangeEvent{
		Timestamp: now,
		From:      fmt.Sprintf("Scope:%d", sm.absoluteScope),
		To:        fmt.Sprintf("TempScope:%d", scope),
		Duration:  ScopeTemporary,
		Reason:    reason,
	})
	fmt.Printf("[Scope] ⏱️  Temporary scope set: %d (TTL: %v, reason: %s)\n", scope, ttl, reason)
}

// ClearTemporaryScope removes the temporary override.
func (sm *ScopeManager) ClearTemporaryScope() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.temporaryScope = nil
	fmt.Println("[Scope] 🧹 Temporary scope cleared")
}

// HasTemporaryScope checks if a temporary scope is active.
func (sm *ScopeManager) HasTemporaryScope() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.temporaryScope == nil {
		return false
	}
	return time.Now().Before(sm.temporaryScope.ExpiresAt)
}

// GetTemporaryScope returns the temporary scope entry (nil if none).
func (sm *ScopeManager) GetTemporaryScope() *TemporaryScopeEntry {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.temporaryScope != nil && time.Now().Before(sm.temporaryScope.ExpiresAt) {
		return sm.temporaryScope
	}
	return nil
}

// ==========================================
// Runtime Enforcement Guards
// ==========================================

// Guard checks if a feature is allowed in the current scope.
// Returns an error with details if blocked — use this at feature entry points.
// Example: if err := scopeManager.Guard("interceptor"); err != nil { return err }
func (sm *ScopeManager) Guard(featureName string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.guardLocked(featureName)
}

// guardLocked is the internal guard — caller MUST hold sm.mu.
func (sm *ScopeManager) guardLocked(featureName string) error {
	f, exists := sm.features[featureName]
	if !exists {
		return fmt.Errorf("[Scope] ❌ BLOCKED: feature '%s' is not registered", featureName)
	}

	// Check 1: Role-based scope
	if !f.Scope.AllowedForRole(sm.currentRole) {
		v := ScopeViolation{
			Timestamp: time.Now(),
			Feature:   featureName,
			Reason:    fmt.Sprintf("not allowed for role %s (requires %s)", sm.currentRole, f.Scope),
			Role:      sm.currentRole,
		}
		sm.violations = append(sm.violations, v)
		return fmt.Errorf("[Scope] ❌ BLOCKED: feature '%s' is not in area %s (scope: %s)",
			featureName, sm.currentRole, f.Scope)
	}

	// Check 2: Cross-feature conflict — active features may block this one
	for activeFeature := range sm.activeFeatures {
		af, ok := sm.features[activeFeature]
		if !ok {
			continue
		}
		for _, conflict := range af.ConflictsWith {
			if conflict == featureName {
				v := ScopeViolation{
					Timestamp: time.Now(),
					Feature:   featureName,
					Reason:    fmt.Sprintf("conflicts with active feature '%s'", activeFeature),
					Caller:    activeFeature,
					Role:      sm.currentRole,
				}
				sm.violations = append(sm.violations, v)
				return fmt.Errorf("[Scope] ❌ BLOCKED: feature '%s' conflicts with active '%s' — is not area",
					featureName, activeFeature)
			}
		}
	}

	// Check 3: The requested feature itself may conflict with active features
	for _, conflict := range f.ConflictsWith {
		if sm.activeFeatures[conflict] {
			v := ScopeViolation{
				Timestamp: time.Now(),
				Feature:   featureName,
				Reason:    fmt.Sprintf("'%s' blocks '%s' from running", featureName, conflict),
				Caller:    conflict,
				Role:      sm.currentRole,
			}
			sm.violations = append(sm.violations, v)
			return fmt.Errorf("[Scope] ❌ BLOCKED: feature '%s' cannot run while '%s' is active",
				featureName, conflict)
		}
	}

	return nil
}

// MustGuard is like Guard but panics on violation.
// Use for internal enforcement where a violation is a programming error.
func (sm *ScopeManager) MustGuard(featureName string) {
	if err := sm.Guard(featureName); err != nil {
		panic(err)
	}
}

// IsNotArea checks if a feature is NOT in the current role's area.
// Returns true if the feature is BLOCKED.
// Example: if scopeManager.IsNotArea("interceptor") { /* blocked */ }
func (sm *ScopeManager) IsNotArea(featureName string) bool {
	return sm.Guard(featureName) != nil
}

// IsNotAreaFor checks if a feature is NOT in the given role's area.
// Does not use the current role — checks against a specific role.
func (sm *ScopeManager) IsNotAreaFor(featureName string, role Role) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	f, exists := sm.features[featureName]
	if !exists {
		return true
	}
	return !f.Scope.AllowedForRole(role)
}

// ActivateFeature marks a feature as currently active.
// Active features enforce cross-feature conflict rules.
func (sm *ScopeManager) ActivateFeature(featureName string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if err := sm.guardLocked(featureName); err != nil {
		return err
	}
	sm.activeFeatures[featureName] = true
	fmt.Printf("[Scope] ✅ Feature '%s' activated\n", featureName)
	return nil
}

// DeactivateFeature removes a feature from the active set.
func (sm *ScopeManager) DeactivateFeature(featureName string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.activeFeatures, featureName)
	fmt.Printf("[Scope] 🔴 Feature '%s' deactivated\n", featureName)
}

// GetActiveFeatures returns all currently active features.
func (sm *ScopeManager) GetActiveFeatures() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]string, 0, len(sm.activeFeatures))
	for name := range sm.activeFeatures {
		result = append(result, name)
	}
	return result
}

// GetViolations returns all recorded scope violations.
func (sm *ScopeManager) GetViolations() []ScopeViolation {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]ScopeViolation, len(sm.violations))
	copy(result, sm.violations)
	return result
}

// ClearViolations clears the violation log.
func (sm *ScopeManager) ClearViolations() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.violations = sm.violations[:0]
}

// ==========================================
// Feature Registry
// ==========================================

// RegisterFeature registers a feature with its scope.
func (sm *ScopeManager) RegisterFeature(f *Feature) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.features[f.Name] = f
}

// IsFeatureAllowed checks if a feature is allowed under the current role.
func (sm *ScopeManager) IsFeatureAllowed(featureName string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	f, exists := sm.features[featureName]
	if !exists {
		return false
	}
	return f.Scope.AllowedForRole(sm.currentRole)
}

// GetFeature returns a registered feature by name.
func (sm *ScopeManager) GetFeature(name string) *Feature {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.features[name]
}

// ListFeatures returns all registered features.
func (sm *ScopeManager) ListFeatures() []*Feature {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]*Feature, 0, len(sm.features))
	for _, f := range sm.features {
		result = append(result, f)
	}
	return result
}

// ListAllowedFeatures returns features allowed for the current role.
func (sm *ScopeManager) ListAllowedFeatures() []*Feature {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]*Feature, 0)
	for _, f := range sm.features {
		if f.Scope.AllowedForRole(sm.currentRole) {
			result = append(result, f)
		}
	}
	return result
}

// ListDeniedFeatures returns features NOT allowed for the current role.
func (sm *ScopeManager) ListDeniedFeatures() []*Feature {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]*Feature, 0)
	for _, f := range sm.features {
		if !f.Scope.AllowedForRole(sm.currentRole) {
			result = append(result, f)
		}
	}
	return result
}

// GetHistory returns the scope change history.
func (sm *ScopeManager) GetHistory() []ScopeChangeEvent {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]ScopeChangeEvent, len(sm.history))
	copy(result, sm.history)
	return result
}

// ==========================================
// Builtin Feature Registration
// ==========================================

// registerBuiltinFeatures registers all NetKit-Go features with their scope.
func (sm *ScopeManager) registerBuiltinFeatures() {
	// === CLIENT-ONLY features ===
	sm.features["proxy_http"] = &Feature{
		Name:        "proxy_http",
		Package:     "pkg/proxy",
		Description: "HTTP/HTTPS forward proxy with MITM interception",
		Scope:       FeatureScopeClientOnly,
		Functions:   []string{"NewRelay", "Start", "RegisterConn", "GetLocalIPForRelay"},
	}
	sm.features["proxy_socks5"] = &Feature{
		Name:        "proxy_socks5",
		Package:     "pkg/proxy",
		Description: "SOCKS5 proxy with UDP ASSOCIATE support",
		Scope:       FeatureScopeClientOnly,
		Functions:   []string{"ParseSOCKS5UDPHeader", "BuildSOCKS5UDPHeader", "HandleUDPAssociate"},
	}
	sm.features["interceptor"] = &Feature{
		Name:        "interceptor",
		Package:     "pkg/interceptor",
		Description: "TLS/SSL MITM interceptor with certificate generation",
		Scope:       FeatureScopeClientOnly,
		Functions:   []string{"InterceptTLS", "InterceptHTTP"},
	}
	sm.features["capture"] = &Feature{
		Name:        "capture",
		Package:     "pkg/capture",
		Description: "Packet capture and analysis",
		Scope:       FeatureScopeClientOnly,
		Functions:   []string{"NewCapture", "Start", "Stop", "SetFilter"},
	}
	sm.features["adblock"] = &Feature{
		Name:        "adblock",
		Package:     "pkg/adblock",
		Description: "Ad blocking with filter list support",
		Scope:       FeatureScopeClientOnly,
		Functions:   []string{"NewAdBlocker", "LoadFilterList", "ShouldBlock"},
	}
	sm.features["dns_spoof"] = &Feature{
		Name:        "dns_spoof",
		Package:     "pkg/protocol/dns",
		Description: "DNS spoofing and custom resolution",
		Scope:       FeatureScopeClientOnly,
		Functions:   []string{"NewDNSSpoofer", "AddHost", "Start", "Stop"},
	}
	sm.features["discovery"] = &Feature{
		Name:        "discovery",
		Package:     "pkg/protocol/discovery",
		Description: "mDNS/SSDP/NBNS service discovery",
		Scope:       FeatureScopeClientOnly,
		Functions:   []string{"ServiceDiscovery.Start", "listenMDNS", "listenSSDP", "listenNBNS"},
	}
	sm.features["session"] = &Feature{
		Name:        "session",
		Package:     "pkg/session",
		Description: "HTTP session tracking and cookie management",
		Scope:       FeatureScopeClientOnly,
		Functions:   []string{"NewTracker", "TrackRequest", "GetSessions"},
	}
	sm.features["stealth"] = &Feature{
		Name:        "stealth",
		Package:     "pkg/security",
		Description: "Stealth mode — invisible interception",
		Scope:       FeatureScopeClientOnly,
		Functions:   []string{"DefaultStealthConfig", "ShouldSuppressHeader"},
	}

	// === SERVER-ONLY features ===
	sm.features["tunnel_server"] = &Feature{
		Name:        "tunnel_server",
		Package:     "pkg/tunnel",
		Description: "NK-Tunnel server: port forwarding, frame mux, public listener",
		Scope:       FeatureScopeServerOnly,
		Functions: []string{
			"NewNKTunnelServer", "NKTunnelServer.Start", "NKTunnelServer.VerifyPort",
			"NKTunnelServer.handleControl", "NKTunnelServer.runFrameLoop",
			"NKTunnelServer.listenPublicRange", "NKTunnelServer.listenPublicUDP",
			"NKTunnelServer.serveHTTPSWithRedirect",
		},
		ConflictsWith: []string{
			"interceptor", // Server CANNOT run MITM on its own traffic
			"capture",     // Server CANNOT sniff client data
			"dns_spoof",   // Server CANNOT spoof DNS
			"adblock",     // Server CANNOT block ads on relay
		},
	}
	sm.features["transfer_server"] = &Feature{
		Name:        "transfer_server",
		Package:     "pkg/transfer",
		Description: "QUIC transfer server: handshake mediator, token validator",
		Scope:       FeatureScopeServerOnly,
		Functions:   []string{"NewTransferServer", "TransferServer.Start", "TransferServer.ValidateToken"},
	}
	sm.features["ipsec"] = &Feature{
		Name:        "ipsec",
		Package:     "pkg/security",
		Description: "IPsec rules: MainMode, QuickMode, Phase1/Phase2 auth",
		Scope:       FeatureScopeServerOnly,
		Functions: []string{
			"NewIPsecPolicy", "IPsecPolicy.AddRule", "IPsecPolicy.Evaluate",
			"NewDefaultMainModeCrypto", "NewDefaultQuickModeCrypto",
			"NewPSKPhase1Auth", "NewCertPhase1Auth",
		},
	}

	// === BOTH (Client + Server) ===
	sm.features["tunnel_client"] = &Feature{
		Name:        "tunnel_client",
		Package:     "pkg/tunnel",
		Description: "NK-Tunnel client: connects to server, maps ports locally",
		Scope:       FeatureScopeBoth,
		Functions: []string{
			"NewNKTunnelClient", "NKTunnelClient.Start", "NKTunnelClient.Stop",
			"NKTunnelClient.GetAssignedPorts", "NKTunnelClient.IsConnected",
		},
		ConflictsWith: []string{
			"interceptor", // Tunnel transport CANNOT activate MITM
			"capture",     // Tunnel transport CANNOT sniff its own data
		},
	}
	sm.features["engine"] = &Feature{
		Name:        "engine",
		Package:     "pkg/engine",
		Description: "Core engine: config, state, connection tracking",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"New", "Engine.Start", "Engine.Stop"},
	}
	sm.features["js_runtime"] = &Feature{
		Name:        "js_runtime",
		Package:     "pkg/js",
		Description: "JavaScript scripting runtime with Goja",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"NewRuntime", "RegisterCryptoModule", "RegisterFlowModule"},
	}
	sm.features["firewall"] = &Feature{
		Name:        "firewall",
		Package:     "pkg/security",
		Description: "Rule-based firewall with CIDR matching",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"NewFirewall", "Firewall.AddRule", "Firewall.Evaluate", "Firewall.RemoveRule"},
	}
	sm.features["bruteforce"] = &Feature{
		Name:        "bruteforce",
		Package:     "pkg/security",
		Description: "Bruteforce detection and IP banning",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"NewBruteforceLimiter", "IsAllowed", "RecordFailure", "RecordSuccess", "UnbanIP"},
	}
	sm.features["mem_reducer"] = &Feature{
		Name:        "mem_reducer",
		Package:     "pkg/mem",
		Description: "Memory optimization and periodic GC",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"New", "Reducer.Reduce", "Reducer.StartPeriodic"},
	}
	sm.features["perf"] = &Feature{
		Name:        "perf",
		Package:     "pkg/perf",
		Description: "Performance monitoring and metrics",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"NewMonitor", "Monitor.Start", "Monitor.Snapshot"},
	}
	sm.features["stack_ipv4"] = &Feature{
		Name:        "stack_ipv4",
		Package:     "pkg/protocol/stack",
		Description: "Raw IPv4/TCP/UDP header crafting and checksum",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"IPv4Header.Serialize", "TCPHeader.Serialize", "UDPHeader.Serialize", "CalculateChecksum"},
	}
	sm.features["stack_ipv6"] = &Feature{
		Name:        "stack_ipv6",
		Package:     "pkg/protocol/stack",
		Description: "IPv6 header crafting with v6 pseudo-header checksums",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"IPv6Header.Serialize", "ParseIPv6Header", "TCPHeader.SerializeV6", "UDPHeader.SerializeV6"},
	}
	sm.features["dtls"] = &Feature{
		Name:        "dtls",
		Package:     "pkg/protocol/dtls",
		Description: "DTLS record/handshake parser, ClientHello with SNI",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"ParseRecordHeader", "ParseHandshakeHeader", "ParseClientHello", "IsDTLSPacket"},
	}
	sm.features["tls"] = &Feature{
		Name:        "tls",
		Package:     "pkg/protocol/tls",
		Description: "TLS interception, CA management, certificate generation",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"NewCA", "CA.GenerateCert", "ParseClientHello"},
	}
	sm.features["cgnat"] = &Feature{
		Name:        "cgnat",
		Package:     "pkg/cgnat",
		Description: "CGNAT detector, NAT breaker, NetBIOS scanner",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"NewDetector", "NATBreaker.AttemptHolePunch", "NetBIOSDetector.ProcessPacket"},
	}
	sm.features["transfer_client"] = &Feature{
		Name:        "transfer_client",
		Package:     "pkg/transfer",
		Description: "QUIC transfer sender/receiver with encryption",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"NewSender", "NewReceiver", "Sender.Send", "Receiver.Receive"},
		ConflictsWith: []string{
			"interceptor",  // Transfer data CANNOT activate MITM
			"capture",      // Transfer data CANNOT activate packet sniffing
			"proxy_http",   // Transfer data CANNOT activate HTTP proxy
			"proxy_socks5", // Transfer data CANNOT activate SOCKS5 proxy
			"dns_spoof",    // Transfer data CANNOT activate DNS spoofing
			"session",      // Transfer data CANNOT sniff sessions
		},
	}
	sm.features["scope_control"] = &Feature{
		Name:        "scope_control",
		Package:     "pkg/security",
		Description: "Network scope: private/public/all boundary enforcement",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"NewScopeController", "ScopeController.IsAllowed"},
	}
	sm.features["exporter"] = &Feature{
		Name:        "exporter",
		Package:     "pkg/exporter",
		Description: "Traffic data exporter (PCAP, JSON, HAR)",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"NewExporter", "Exporter.Export"},
	}
	sm.features["logger"] = &Feature{
		Name:        "logger",
		Package:     "pkg/logger",
		Description: "Structured logging with rotation",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"New", "Logger.Info", "Logger.Error", "Logger.Debug"},
	}
	sm.features["proxy_universal"] = &Feature{
		Name:        "proxy_universal",
		Package:     "pkg/proxy",
		Description: "Universal dialer: proxy/WireGuard upstream connector",
		Scope:       FeatureScopeBoth,
		Functions:   []string{"UniversalDialer.Dial", "UniversalDialer.DialContext"},
	}
}
