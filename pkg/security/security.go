// Package security provides security features for NetKit-Go including
// bruteforce detection, firewall rules, network scope control, and stealth mode.
package security

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// BruteforceLimiter tracks authentication attempts per IP and rate-limits
// excessive failures. Used in SOCKS5 and tunnel authentication.
type BruteforceLimiter struct {
	mu          sync.RWMutex
	attempts    map[string]*AttemptRecord
	maxAttempts int
	banDuration time.Duration
	window      time.Duration
}

// AttemptRecord tracks auth attempts from a single IP.
type AttemptRecord struct {
	Failures  int
	FirstFail time.Time
	LastFail  time.Time
	BannedAt  time.Time
	Banned    bool
}

// NewBruteforceLimiter creates a new limiter.
// maxAttempts: max failures before ban
// window: time window for counting failures
// banDuration: how long to ban offending IPs
func NewBruteforceLimiter(maxAttempts int, window, banDuration time.Duration) *BruteforceLimiter {
	bl := &BruteforceLimiter{
		attempts:    make(map[string]*AttemptRecord),
		maxAttempts: maxAttempts,
		banDuration: banDuration,
		window:      window,
	}
	go bl.cleanupLoop()
	return bl
}

// IsAllowed checks if an IP is allowed to attempt authentication.
func (bl *BruteforceLimiter) IsAllowed(ip string) bool {
	bl.mu.RLock()
	record, exists := bl.attempts[ip]
	bl.mu.RUnlock()

	if !exists {
		return true
	}

	if record.Banned {
		if time.Since(record.BannedAt) > bl.banDuration {
			// Ban expired
			bl.mu.Lock()
			delete(bl.attempts, ip)
			bl.mu.Unlock()
			return true
		}
		return false
	}

	return true
}

// RecordFailure records a failed authentication attempt.
// Returns true if the IP is now banned.
func (bl *BruteforceLimiter) RecordFailure(ip string) bool {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	record, exists := bl.attempts[ip]
	if !exists {
		record = &AttemptRecord{
			Failures:  0,
			FirstFail: time.Now(),
		}
		bl.attempts[ip] = record
	}

	now := time.Now()

	// Reset window if first failure was too long ago
	if now.Sub(record.FirstFail) > bl.window {
		record.Failures = 0
		record.FirstFail = now
	}

	record.Failures++
	record.LastFail = now

	if record.Failures >= bl.maxAttempts {
		record.Banned = true
		record.BannedAt = now
		fmt.Printf("[Security] 🚫 IP %s BANNED for %v (exceeded %d failed attempts)\n", ip, bl.banDuration, bl.maxAttempts)
		return true
	}

	return false
}

// RecordSuccess clears failure history for an IP (successful auth).
func (bl *BruteforceLimiter) RecordSuccess(ip string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	delete(bl.attempts, ip)
}

// GetBannedIPs returns all currently banned IPs.
func (bl *BruteforceLimiter) GetBannedIPs() []string {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	var banned []string
	for ip, record := range bl.attempts {
		if record.Banned && time.Since(record.BannedAt) < bl.banDuration {
			banned = append(banned, ip)
		}
	}
	return banned
}

// UnbanIP manually unbans an IP.
func (bl *BruteforceLimiter) UnbanIP(ip string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	delete(bl.attempts, ip)
}

// cleanupLoop periodically removes expired records.
func (bl *BruteforceLimiter) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		bl.mu.Lock()
		now := time.Now()
		for ip, record := range bl.attempts {
			if record.Banned && now.Sub(record.BannedAt) > bl.banDuration {
				delete(bl.attempts, ip)
			} else if !record.Banned && now.Sub(record.LastFail) > bl.window*2 {
				delete(bl.attempts, ip)
			}
		}
		bl.mu.Unlock()
	}
}

// FirewallAction defines what to do with a matched packet.
type FirewallAction int

const (
	FirewallAllow FirewallAction = iota
	FirewallDeny
	FirewallLog
)

func (a FirewallAction) String() string {
	switch a {
	case FirewallAllow:
		return "ALLOW"
	case FirewallDeny:
		return "DENY"
	case FirewallLog:
		return "LOG"
	default:
		return "UNKNOWN"
	}
}

// FirewallDirection specifies traffic direction.
type FirewallDirection int

const (
	DirectionInbound FirewallDirection = iota
	DirectionOutbound
	DirectionBoth
)

func (d FirewallDirection) String() string {
	switch d {
	case DirectionInbound:
		return "IN"
	case DirectionOutbound:
		return "OUT"
	case DirectionBoth:
		return "BOTH"
	default:
		return "UNKNOWN"
	}
}

// FirewallRule defines a single firewall rule.
type FirewallRule struct {
	Name      string
	Priority  int // Lower = higher priority
	Action    FirewallAction
	Direction FirewallDirection
	SrcIP     string // CIDR or exact IP, empty = any
	DstIP     string
	SrcPort   int // 0 = any
	DstPort   int
	Protocol  string // "tcp", "udp", "", empty = any
	Enabled   bool
}

// Firewall is a rule-based packet filter.
type Firewall struct {
	mu    sync.RWMutex
	rules []FirewallRule
}

// NewFirewall creates a new firewall with no rules (default allow).
func NewFirewall() *Firewall {
	return &Firewall{
		rules: make([]FirewallRule, 0),
	}
}

// AddRule adds a firewall rule.
func (fw *Firewall) AddRule(rule FirewallRule) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.rules = append(fw.rules, rule)
}

// RemoveRule removes a rule by name.
func (fw *Firewall) RemoveRule(name string) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	for i := range fw.rules {
		if fw.rules[i].Name == name {
			fw.rules = append(fw.rules[:i], fw.rules[i+1:]...)
			return
		}
	}
}

// Evaluate checks a connection against all rules.
// Returns the action from the highest-priority matching rule.
// If no rule matches, returns FirewallAllow (default allow).
func (fw *Firewall) Evaluate(srcIP string, srcPort int, dstIP string, dstPort int, protocol string, direction FirewallDirection) FirewallAction {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	bestPriority := int(^uint(0) >> 1) // MaxInt
	bestAction := FirewallAllow

	for _, rule := range fw.rules {
		if !rule.Enabled {
			continue
		}
		if rule.Direction != DirectionBoth && rule.Direction != direction {
			continue
		}
		if rule.Protocol != "" {
			matched := false
			for _, proto := range strings.Split(rule.Protocol, "|") {
				if strings.TrimSpace(proto) == protocol {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if rule.SrcPort != 0 && rule.SrcPort != srcPort {
			continue
		}
		if rule.DstPort != 0 && rule.DstPort != dstPort {
			continue
		}
		if rule.SrcIP != "" && !matchIP(srcIP, rule.SrcIP) {
			continue
		}
		if rule.DstIP != "" && !matchIP(dstIP, rule.DstIP) {
			continue
		}

		// Rule matches
		if rule.Priority < bestPriority {
			bestPriority = rule.Priority
			bestAction = rule.Action
		}
	}

	return bestAction
}

// matchIP checks if an IP matches a pattern (exact or CIDR).
func matchIP(ip, pattern string) bool {
	if ip == pattern {
		return true
	}
	_, cidr, err := net.ParseCIDR(pattern)
	if err != nil {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return cidr.Contains(parsed)
}

// ListRules returns all rules.
func (fw *Firewall) ListRules() []FirewallRule {
	fw.mu.RLock()
	defer fw.mu.RUnlock()
	result := make([]FirewallRule, len(fw.rules))
	copy(result, fw.rules)
	return result
}

// NetworkScope defines the allowed network boundaries.
type NetworkScope int

const (
	ScopePrivateOnly NetworkScope = iota // Only private IPs
	ScopePublicOnly                      // Only public IPs
	ScopeAll                             // Both private and public
)

func (s NetworkScope) String() string {
	switch s {
	case ScopePrivateOnly:
		return "PrivateOnly"
	case ScopePublicOnly:
		return "PublicOnly"
	case ScopeAll:
		return "All"
	default:
		return "Unknown"
	}
}

// ScopeController enforces network boundaries.
type ScopeController struct {
	scope NetworkScope
}

// NewScopeController creates a new scope controller.
func NewScopeController(scope NetworkScope) *ScopeController {
	return &ScopeController{scope: scope}
}

// IsAllowed checks if a destination IP is within the allowed scope.
func (sc *ScopeController) IsAllowed(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	isPriv := IsPrivateIP(parsed)

	switch sc.scope {
	case ScopePrivateOnly:
		return isPriv
	case ScopePublicOnly:
		return !isPriv
	case ScopeAll:
		return true
	}
	return false
}

func IsPrivateIP(ip net.IP) bool {
	privateRanges := []*net.IPNet{
		// IPv4
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
		{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		// IPv6
		{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},   // Loopback
		{IP: net.ParseIP("fe80::"), Mask: net.CIDRMask(10, 128)}, // Link-local
		{IP: net.ParseIP("fc00::"), Mask: net.CIDRMask(7, 128)},  // Unique Local Address (ULA)
	}
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// StealthConfig configures stealth interception.
// In stealth mode, the interceptor is invisible to the client:
// - No modified headers
// - No extra latency fingerprinting
// - No detectable certificate anomalies
// - Traffic appears as direct connection
type StealthConfig struct {
	Enabled          bool
	SuppressHeaders  bool // Remove/avoid injecting proxy headers
	MimicTTL         bool // Match expected TTL for the route
	RandomizeTimings bool // Add jitter to avoid timing analysis
	HideFromClient   bool // Prevent client from detecting interception
}

// DefaultStealthConfig returns a config optimized for maximum stealth.
func DefaultStealthConfig() *StealthConfig {
	return &StealthConfig{
		Enabled:          true,
		SuppressHeaders:  true,
		MimicTTL:         true,
		RandomizeTimings: true,
		HideFromClient:   true,
	}
}

// ShouldSuppressHeader checks if a specific header should be removed/hidden.
func (sc *StealthConfig) ShouldSuppressHeader(header string) bool {
	if !sc.SuppressHeaders {
		return false
	}
	// Headers that reveal proxying
	suppressList := map[string]bool{
		"Via":               true,
		"X-Forwarded-For":   true,
		"X-Forwarded-Proto": true,
		"X-Forwarded-Host":  true,
		"Proxy-Connection":  true,
		"X-Proxy-ID":        true,
		"Forwarded":         true,
		"X-Real-IP":         true,
		"X-NetKit":          true,
	}
	return suppressList[header]
}
