package network

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
)

// ECHConfig represents Encrypted Client Hello configuration
type ECHConfig struct {
	Enabled      bool     `json:"enabled"`
	PublicName   string   `json:"public_name"`   // Outer SNI (public-facing)
	ConfigID     uint8    `json:"config_id"`     // ECH config ID
	Version      uint16   `json:"version"`       // ECH version (0xfe0d for draft-13)
	CipherSuites []uint16 `json:"cipher_suites"` // AEAD cipher suites
	MaxNameLen   uint8    `json:"max_name_len"`  // Maximum inner name length
}

// TLSExtensions represents dynamic TLS extension configuration
type TLSExtensions struct {
	// ECH Configuration
	ECH *ECHConfig `json:"ech"`

	// ALPN (Application-Layer Protocol Negotiation)
	ALPN []string `json:"alpn"`

	// Supported versions
	SupportedVersions []uint16 `json:"supported_versions"`

	// Signature algorithms
	SignatureAlgorithms []uint16 `json:"signature_algorithms"`

	// Supported groups (curves)
	SupportedGroups []uint16 `json:"supported_groups"`

	// Key share groups
	KeyShareGroups []uint16 `json:"key_share_groups"`

	// PSK key exchange modes
	PSKModes []uint8 `json:"psk_modes"`

	// Certificate compression algorithms
	CertCompAlgs []uint16 `json:"cert_comp_algs"`

	// Record size limit
	RecordSizeLimit uint16 `json:"record_size_limit"`

	// Delegated credentials
	DelegatedCredentials bool `json:"delegated_credentials"`

	// Early data
	EarlyData bool `json:"early_data"`

	// GREASE values (random values for anti-fingerprinting)
	GREASEExtensions []uint16 `json:"grease_extensions"`
	GREASECiphers    []uint16 `json:"grease_ciphers"`
	GREASEGroups     []uint16 `json:"grease_groups"`
}

// Pre-defined GREASE values
var greaseValues = []uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

// ALPN protocol variations
var alpnProtocols = [][]string{
	{"h2", "http/1.1"},
	{"h2"},
	{"http/1.1", "h2"},
	{"h2", "http/1.1", "http/1.0"},
}

// Signature algorithm variations
var signatureAlgorithmsVariations = [][]uint16{
	{0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301},
	{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201},
	{0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0401, 0x0501, 0x0601},
}

// Supported groups variations
var supportedGroupsVariations = [][]uint16{
	{0x001d, 0x0017, 0x0018, 0x001e, 0x0019, 0x0100, 0x0101},         // Chrome
	{0x001d, 0x0017, 0x0018, 0x001e, 0x0100, 0x0101, 0x0102, 0x0103}, // Firefox
	{0x001d, 0x0017, 0x0018, 0x0019},                                 // Safari
	{0x001d, 0x0017, 0x001e, 0x0019, 0x0018},                         // Edge
}

// NewTLSExtensions creates dynamic TLS extensions based on browser type
func NewTLSExtensions(browserType string) *TLSExtensions {
	ext := &TLSExtensions{
		ECH:             NewECHConfig(),
		RecordSizeLimit: 16385,
		EarlyData:       randomBool(),
	}

	// Random GREASE values
	ext.GREASEExtensions = selectRandomGREASE(2)
	ext.GREASECiphers = selectRandomGREASE(1)
	ext.GREASEGroups = selectRandomGREASE(1)

	// Browser-specific configurations
	switch {
	case contains(browserType, "Chrome"), contains(browserType, "Edge"):
		ext.applyChrome()
	case contains(browserType, "Firefox"):
		ext.applyFirefox()
	case contains(browserType, "Safari"), contains(browserType, "iOS"):
		ext.applySafari()
	default:
		ext.applyChrome()
	}

	// Add randomization
	ext.randomize()

	return ext
}

func (ext *TLSExtensions) applyChrome() {
	ext.ALPN = []string{"h2", "http/1.1"}
	ext.SupportedVersions = []uint16{0x0304, 0x0303} // TLS 1.3, TLS 1.2
	ext.SignatureAlgorithms = signatureAlgorithmsVariations[0]
	ext.SupportedGroups = supportedGroupsVariations[0]
	ext.KeyShareGroups = []uint16{0x001d, 0x0017} // X25519, secp256r1
	ext.PSKModes = []uint8{0x01}                  // PSK with (EC)DHE
	ext.CertCompAlgs = []uint16{0x0002}           // brotli
	ext.DelegatedCredentials = true
}

func (ext *TLSExtensions) applyFirefox() {
	ext.ALPN = []string{"h2", "http/1.1"}
	ext.SupportedVersions = []uint16{0x0304, 0x0303}
	ext.SignatureAlgorithms = signatureAlgorithmsVariations[1]
	ext.SupportedGroups = supportedGroupsVariations[1]
	ext.KeyShareGroups = []uint16{0x001d, 0x0017, 0x0100} // X25519, P-256, X25519Kyber768
	ext.PSKModes = []uint8{0x01}
	ext.CertCompAlgs = []uint16{0x0002, 0x0001} // brotli, zlib
	ext.DelegatedCredentials = true
}

func (ext *TLSExtensions) applySafari() {
	ext.ALPN = []string{"h2", "http/1.1"}
	ext.SupportedVersions = []uint16{0x0304, 0x0303, 0x0302}
	ext.SignatureAlgorithms = signatureAlgorithmsVariations[2]
	ext.SupportedGroups = supportedGroupsVariations[2]
	ext.KeyShareGroups = []uint16{0x001d, 0x0017}
	ext.PSKModes = []uint8{0x01}
	ext.CertCompAlgs = []uint16{0x0002}
	ext.DelegatedCredentials = false
}

func (ext *TLSExtensions) randomize() {
	// Randomize ALPN order occasionally
	if randomBool() && len(ext.ALPN) > 1 {
		ext.ALPN = shuffleStrings(ext.ALPN)
	}

	// Add/remove optional extensions randomly
	if randomBool() {
		ext.EarlyData = !ext.EarlyData
	}

	// Slight variations in record size limit
	ext.RecordSizeLimit = uint16(16384 + randomInt(3)) // 16384-16386
}

// NewECHConfig creates a new ECH configuration
func NewECHConfig() *ECHConfig {
	return &ECHConfig{
		Enabled:    true,
		PublicName: generateRandomPublicName(),
		ConfigID:   uint8(randomInt(256)),
		Version:    0xfe0d, // ECH draft-13
		CipherSuites: []uint16{
			0x0001, // AEAD_AES_128_GCM
			0x0002, // AEAD_AES_256_GCM
			0x0003, // AEAD_ChaCha20Poly1305
		},
		MaxNameLen: 128,
	}
}

// GetECHConfigList returns encoded ECH config list
func (c *ECHConfig) GetECHConfigList() []byte {
	// Simplified ECH config encoding
	// In production, this would be a proper TLS-encoded ECHConfigList
	config := make([]byte, 32)
	rand.Read(config)
	config[0] = byte(c.Version >> 8)
	config[1] = byte(c.Version & 0xff)
	config[2] = c.ConfigID
	return config
}

// String returns a unique ECH identifier
func (c *ECHConfig) String() string {
	return fmt.Sprintf("ECH[v=%04x,id=%d,pub=%s]", c.Version, c.ConfigID, c.PublicName[:8])
}

// String returns a unique extension fingerprint
func (ext *TLSExtensions) String() string {
	return fmt.Sprintf("Ext[ALPN=%v,Groups=%d,ECH=%v]",
		ext.ALPN, len(ext.SupportedGroups), ext.ECH.Enabled)
}

// GetExtensionFingerprint returns a unique fingerprint for TLS extensions
func (ext *TLSExtensions) GetExtensionFingerprint() string {
	// Create a fingerprint based on extension configuration
	grease := "G:" + fmt.Sprintf("%04x", ext.GREASEExtensions[0])
	alpn := "A:" + ext.ALPN[0]
	groups := fmt.Sprintf("SG:%d", len(ext.SupportedGroups))
	ech := fmt.Sprintf("ECH:%d", ext.ECH.ConfigID)

	return grease + "|" + alpn + "|" + groups + "|" + ech
}

// Helper functions
func selectRandomGREASE(count int) []uint16 {
	result := make([]uint16, count)
	for i := 0; i < count; i++ {
		result[i] = greaseValues[randomInt(len(greaseValues))]
	}
	return result
}

func generateRandomPublicName() string {
	// Generate random cloudflare-like ECH public names
	names := []string{
		"cloudflare-ech.com",
		"crypto.cloudflare.com",
		"ech.cloudflare.com",
		"tls-ech.cloudflareresearch.com",
		"encryptedsni.com",
	}
	return names[randomInt(len(names))]
}

func randomBool() bool {
	n, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return false
	}
	return n.Int64() == 1
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func shuffleStrings(slice []string) []string {
	result := make([]string, len(slice))
	copy(result, slice)
	for i := len(result) - 1; i > 0; i-- {
		j := randomInt(i + 1)
		result[i], result[j] = result[j], result[i]
	}
	return result
}

// GenerateRandomClientHelloID generates a randomized client hello ID
func GenerateRandomClientHelloID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:11]
}

// randomInt returns a random integer between 0 and max (exclusive)
func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}
