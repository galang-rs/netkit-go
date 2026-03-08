package security

import (
	"fmt"
	"time"
)

// IPsecAction defines what happens when an IPsec rule matches.
type IPsecAction int

const (
	IPsecActionAllow IPsecAction = iota
	IPsecActionBlock
	IPsecActionRequireEncryption
)

func (a IPsecAction) String() string {
	switch a {
	case IPsecActionAllow:
		return "Allow"
	case IPsecActionBlock:
		return "Block"
	case IPsecActionRequireEncryption:
		return "RequireEncryption"
	default:
		return fmt.Sprintf("Unknown(%d)", int(a))
	}
}

// IPsecRule defines a base IPsec rule.
type IPsecRule struct {
	Name        string
	Description string
	Action      IPsecAction
	SrcAddress  string // CIDR or IP
	DstAddress  string
	Protocol    string // "tcp", "udp", "any"
	SrcPort     int
	DstPort     int
	Enabled     bool
	Created     time.Time
}

// IPsecMainModeCryptoSet defines IKE Phase 1 (Main Mode) cryptographic parameters.
type IPsecMainModeCryptoSet struct {
	Name               string
	Description        string
	Encryption         string // "AES128", "AES256", "3DES"
	Hash               string // "SHA256", "SHA384", "SHA1", "MD5"
	DHGroup            int    // Diffie-Hellman group: 14, 19, 20, 21
	KeyLifetimeMinutes int
}

// NewDefaultMainModeCrypto returns a secure default Main Mode crypto set.
func NewDefaultMainModeCrypto() *IPsecMainModeCryptoSet {
	return &IPsecMainModeCryptoSet{
		Name:               "default-main",
		Description:        "AES-256 + SHA-256 + DH Group 14",
		Encryption:         "AES256",
		Hash:               "SHA256",
		DHGroup:            14,
		KeyLifetimeMinutes: 480, // 8 hours
	}
}

// IPsecQuickModeCryptoSet defines IKE Phase 2 (Quick Mode) cryptographic parameters.
type IPsecQuickModeCryptoSet struct {
	Name                 string
	Description          string
	Encryption           string // "AES128-GCM", "AES256-GCM", "AES256-CBC"
	Integrity            string // "SHA256", "SHA1" (not needed for GCM)
	PFS                  bool   // Perfect Forward Secrecy
	PFSGroup             int    // DH group for PFS
	KeyLifetimeMinutes   int
	KeyLifetimeKilobytes int
}

// NewDefaultQuickModeCrypto returns a secure default Quick Mode crypto set.
func NewDefaultQuickModeCrypto() *IPsecQuickModeCryptoSet {
	return &IPsecQuickModeCryptoSet{
		Name:                 "default-quick",
		Description:          "AES-256-GCM + PFS DH14",
		Encryption:           "AES256-GCM",
		Integrity:            "", // GCM provides integrity
		PFS:                  true,
		PFSGroup:             14,
		KeyLifetimeMinutes:   60,
		KeyLifetimeKilobytes: 0, // No byte limit
	}
}

// IPsecPhase1AuthSet defines Phase 1 authentication methods.
type IPsecPhase1AuthSet struct {
	Name        string
	Description string
	Method      string // "PreSharedKey", "Certificate", "EAP"
	PSK         string // Pre-shared key (if method = PreSharedKey)
	CertPath    string // Certificate path (if method = Certificate)
}

// NewPSKPhase1Auth creates a PSK-based Phase 1 auth set.
func NewPSKPhase1Auth(name, psk string) *IPsecPhase1AuthSet {
	return &IPsecPhase1AuthSet{
		Name:        name,
		Description: "Pre-Shared Key authentication",
		Method:      "PreSharedKey",
		PSK:         psk,
	}
}

// NewCertPhase1Auth creates a certificate-based Phase 1 auth set.
func NewCertPhase1Auth(name, certPath string) *IPsecPhase1AuthSet {
	return &IPsecPhase1AuthSet{
		Name:        name,
		Description: "Certificate-based authentication",
		Method:      "Certificate",
		CertPath:    certPath,
	}
}

// IPsecPhase2AuthSet defines Phase 2 authentication methods.
type IPsecPhase2AuthSet struct {
	Name        string
	Description string
	AuthMethod  string // "ComputerKerberos", "ComputerCert", "UserCert", "Anonymous"
}

// IPsecPolicy combines all IPsec components into a policy.
type IPsecPolicy struct {
	Name            string
	Rules           []IPsecRule
	MainModeCrypto  *IPsecMainModeCryptoSet
	QuickModeCrypto *IPsecQuickModeCryptoSet
	Phase1Auth      *IPsecPhase1AuthSet
	Phase2Auth      *IPsecPhase2AuthSet
	Enabled         bool
}

// NewIPsecPolicy creates a new policy with default crypto.
func NewIPsecPolicy(name string) *IPsecPolicy {
	return &IPsecPolicy{
		Name:            name,
		Rules:           make([]IPsecRule, 0),
		MainModeCrypto:  NewDefaultMainModeCrypto(),
		QuickModeCrypto: NewDefaultQuickModeCrypto(),
		Enabled:         true,
	}
}

// AddRule adds a rule to the policy.
func (p *IPsecPolicy) AddRule(rule IPsecRule) {
	rule.Created = time.Now()
	p.Rules = append(p.Rules, rule)
}

// Evaluate checks if a connection matches any IPsec rule.
func (p *IPsecPolicy) Evaluate(srcAddr, dstAddr, protocol string, srcPort, dstPort int) IPsecAction {
	if !p.Enabled {
		return IPsecActionAllow
	}

	for _, rule := range p.Rules {
		if !rule.Enabled {
			continue
		}
		if rule.Protocol != "any" && rule.Protocol != protocol {
			continue
		}
		if rule.SrcPort != 0 && rule.SrcPort != srcPort {
			continue
		}
		if rule.DstPort != 0 && rule.DstPort != dstPort {
			continue
		}
		if rule.SrcAddress != "" && !matchIP(srcAddr, rule.SrcAddress) {
			continue
		}
		if rule.DstAddress != "" && !matchIP(dstAddr, rule.DstAddress) {
			continue
		}
		return rule.Action
	}

	return IPsecActionAllow
}
