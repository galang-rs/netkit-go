// Package network provides TLS fingerprint isolation for HTTP clients
package network

import (
	"fmt"
	"reflect"
	"sync"

	utls "github.com/bogdanfinn/utls"
)

// TLSProfile represents a browser TLS fingerprint profile
type TLSProfile struct {
	Name              string             `json:"name"`
	ClientHello       utls.ClientHelloID `json:"-"` // Revert serialization: utls.ClientHelloID contains functions
	UserAgent         string             `json:"user_agent"`
	Platform          string             `json:"platform"`
	Vendor            string             `json:"vendor"`
	SecChUa           string             `json:"sec_ch_ua"` // e.g. "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\""
	SecChUaMobile     string             `json:"sec_ch_ua_mobile"`
	SecChUaPlatform   string             `json:"sec_ch_ua_platform"`
	PseudoHeaderOrder []string           `json:"pseudo_header_order"`

	// HTTP/2 Settings
	InitialWindowSize uint32 `json:"initial_window_size"`
	MaxFrameSize      uint32 `json:"max_frame_size"`
	MaxHeaderListSize uint32 `json:"max_header_list_size"`
	HeaderTableSize   uint32 `json:"header_table_size"`
	EnablePush        bool   `json:"enable_push"`

	// Cached extension order for fingerprint consistency (generated once, reused across dials)
	extensionOrder []string              `json:"-"`
	Spec           *utls.ClientHelloSpec `json:"-"` // kept only for compatibility - not shared directly
	specOnce       sync.Once             `json:"-"`
}

// Pre-defined browser profiles
var (
	ProfileChrome120 = &TLSProfile{
		Name:              "Chrome120",
		ClientHello:       utls.HelloChrome_120,
		UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Platform:          "Win32",
		Vendor:            "Google Inc.",
		SecChUa:           "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
		SecChUaMobile:     "?0",
		SecChUaPlatform:   "\"Windows\"",
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		InitialWindowSize: 6291456,
		MaxFrameSize:      16384,
		MaxHeaderListSize: 262144,
		HeaderTableSize:   65536,
		EnablePush:        false,
	}

	// Edge profiles
	ProfileEdge = &TLSProfile{
		Name:              "Edge",
		ClientHello:       utls.HelloEdge_85,
		UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		Platform:          "Win32",
		Vendor:            "Google Inc.",
		SecChUa:           "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
		SecChUaMobile:     "?0",
		SecChUaPlatform:   "\"Windows\"",
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		InitialWindowSize: 6291456,
		MaxFrameSize:      16384,
		MaxHeaderListSize: 262144,
		HeaderTableSize:   65536,
		EnablePush:        false,
	}

	// Android profiles
	ProfileAndroid = &TLSProfile{
		Name:              "Android",
		ClientHello:       utls.HelloChrome_Auto,
		UserAgent:         "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		Platform:          "Linux armv8l",
		Vendor:            "Google Inc.",
		SecChUa:           "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
		SecChUaMobile:     "?1",
		SecChUaPlatform:   "\"Android\"",
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		InitialWindowSize: 6291456,
		MaxFrameSize:      16384,
		MaxHeaderListSize: 262144,
		HeaderTableSize:   65536,
		EnablePush:        false,
	}

	ProfileIOS = &TLSProfile{
		Name:              "iOS",
		ClientHello:       utls.HelloIOS_16_0,
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
		Platform:          "iPhone",
		Vendor:            "Apple Inc.",
		SecChUa:           "",
		SecChUaMobile:     "?1",
		SecChUaPlatform:   "\"iOS\"",
		PseudoHeaderOrder: []string{":method", ":scheme", ":path", ":authority"},
		InitialWindowSize: 2097152,
		MaxFrameSize:      16384,
		MaxHeaderListSize: 0,
		HeaderTableSize:   4096,
		EnablePush:        true,
	}

	ProfileSafari = &TLSProfile{
		Name:              "Safari",
		ClientHello:       utls.HelloSafari_16_0,
		UserAgent:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
		Platform:          "MacIntel",
		Vendor:            "Apple Inc.",
		SecChUa:           "",
		SecChUaMobile:     "?0",
		SecChUaPlatform:   "\"macOS\"",
		PseudoHeaderOrder: []string{":method", ":scheme", ":path", ":authority"},
		InitialWindowSize: 2097152,
		MaxFrameSize:      16384,
		MaxHeaderListSize: 0,
		HeaderTableSize:   4096,
		EnablePush:        true,
	}

	ProfileMobileSafari = &TLSProfile{
		Name:              "MobileSafari",
		ClientHello:       utls.HelloIOS_16_0,
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
		Platform:          "iPhone",
		Vendor:            "Apple Inc.",
		SecChUa:           "",
		SecChUaMobile:     "?1",
		SecChUaPlatform:   "\"iOS\"",
		PseudoHeaderOrder: []string{":method", ":scheme", ":path", ":authority"},
		InitialWindowSize: 2097152,
		MaxFrameSize:      16384,
		MaxHeaderListSize: 0,
		HeaderTableSize:   4096,
		EnablePush:        true,
	}

	// Newer Chrome
	ProfileChrome117 = &TLSProfile{
		Name:              "Chrome117",
		ClientHello:       utls.HelloChrome_111, // Use a concrete version close to 117
		UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
		Platform:          "Win32",
		Vendor:            "Google Inc.",
		SecChUa:           "\"Google Chrome\";v=\"117\", \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"117\"",
		SecChUaMobile:     "?0",
		SecChUaPlatform:   "\"Windows\"",
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		InitialWindowSize: 6291456,
		MaxFrameSize:      16384,
		MaxHeaderListSize: 262144,
		HeaderTableSize:   65536,
		EnablePush:        false,
	}

	// Firefox
	ProfileFirefox117 = &TLSProfile{
		Name:              "Firefox117",
		ClientHello:       utls.HelloFirefox_120,
		UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0",
		Platform:          "Win32",
		Vendor:            "",
		SecChUa:           "", // Firefox doesn't typically send sec-ch-ua
		SecChUaMobile:     "?0",
		SecChUaPlatform:   "\"Windows\"",
		PseudoHeaderOrder: []string{":method", ":path", ":authority", ":scheme"},
		InitialWindowSize: 131072,
		MaxFrameSize:      16384,
		MaxHeaderListSize: 0,
		HeaderTableSize:   65536,
		EnablePush:        false,
	}

	ProfileSafari16 = &TLSProfile{
		Name:              "Safari16",
		ClientHello:       utls.HelloIOS_Auto, // Best approximation for Safari
		UserAgent:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
		Platform:          "MacIntel",
		Vendor:            "Apple Computer, Inc.",
		SecChUa:           "",
		SecChUaMobile:     "?0",
		SecChUaPlatform:   "\"macOS\"",
		PseudoHeaderOrder: []string{":method", ":scheme", ":path", ":authority"},
		InitialWindowSize: 2097152,
		MaxFrameSize:      16384,
		MaxHeaderListSize: 0,
		HeaderTableSize:   4096,
		EnablePush:        true,
	}

	// Native Golang TLS
	ProfileNative = &TLSProfile{
		Name:        "Native",
		ClientHello: utls.HelloGolang,
		UserAgent:   "Go-http-client/1.1",
	}
)

// AllProfiles contains all available TLS profiles
// Expanded to include more variants for better rotation and Cloudflare evasion
var AllProfiles = []*TLSProfile{
	ProfileChrome120,
	ProfileChrome117,
	ProfileEdge,
	ProfileFirefox117,   // Added for diversity
	ProfileSafari16,     // Added for diversity
	ProfileIOS,          // New iOS profile
	ProfileSafari,       // New Safari profile
	ProfileMobileSafari, // New Mobile Safari profile
}

// GetRandomProfile returns a random TLS profile with weighted selection favoring Chrome/Edge
// Chrome/Edge profiles are preferred (60% chance) for better Cloudflare bypass success
func GetRandomProfile() *TLSProfile {
	// Weighted selection: 60% Chrome/Edge, 40% others
	roll := randomInt(100)
	if roll < 60 {
		// Chrome/Edge profiles (index 0, 1, 2)
		idx := randomInt(3)
		return AllProfiles[idx]
	}
	// All profiles including Firefox/Safari
	idx := randomInt(len(AllProfiles))
	return AllProfiles[idx]
}

// GetProfileByName returns a profile by its name
func GetProfileByName(name string) (*TLSProfile, error) {
	for _, p := range AllProfiles {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, fmt.Errorf("profile not found: %s", name)
}

// Clone creates a copy of the TLS profile
func (p *TLSProfile) Clone() *TLSProfile {
	clone := &TLSProfile{
		Name:              p.Name,
		ClientHello:       p.ClientHello,
		UserAgent:         p.UserAgent,
		Platform:          p.Platform,
		Vendor:            p.Vendor,
		SecChUa:           p.SecChUa,
		SecChUaMobile:     p.SecChUaMobile,
		SecChUaPlatform:   p.SecChUaPlatform,
		PseudoHeaderOrder: p.PseudoHeaderOrder,
		InitialWindowSize: p.InitialWindowSize,
		MaxFrameSize:      p.MaxFrameSize,
		MaxHeaderListSize: p.MaxHeaderListSize,
		HeaderTableSize:   p.HeaderTableSize,
		EnablePush:        p.EnablePush,
	}
	// Pre-cache the extension order immediately so every clone
	// has the same fixed extension ordering from the start.
	clone.EnsureSpec()
	return clone
}

// EnsureSpec generates the initial spec to cache the extension order.
// This pins the extension order (which ShuffleChromeTLSExtensions randomizes)
// so that all connections using this profile have a consistent JA3 fingerprint.
func (p *TLSProfile) EnsureSpec() {
	p.specOnce.Do(func() {
		if p.ClientHello.Str() == utls.HelloCustom.Str() || p.ClientHello.Str() == utls.HelloGolang.Str() {
			return
		}
		spec, err := utls.UTLSIdToSpec(p.ClientHello)
		if err == nil {
			p.Spec = &spec
			// Cache the extension type order
			p.extensionOrder = make([]string, len(spec.Extensions))
			for i, ext := range spec.Extensions {
				p.extensionOrder[i] = reflect.TypeOf(ext).String()
			}
		}
	})
}

// NewOrderedSpec generates a fresh ClientHelloSpec with new extension instances
// but re-sorted to match the cached extension order for JA3 consistency.
func (p *TLSProfile) NewOrderedSpec() (*utls.ClientHelloSpec, error) {
	p.EnsureSpec()
	if p.extensionOrder == nil {
		return nil, fmt.Errorf("no cached extension order")
	}

	// Generate a fresh spec (new extension instances, no shared state)
	freshSpec, err := utls.UTLSIdToSpec(p.ClientHello)
	if err != nil {
		return nil, err
	}

	// Re-sort the fresh spec's extensions to match the cached order
	ordered := make([]utls.TLSExtension, 0, len(freshSpec.Extensions))
	remaining := make([]utls.TLSExtension, len(freshSpec.Extensions))
	copy(remaining, freshSpec.Extensions)

	for _, typeName := range p.extensionOrder {
		for j, ext := range remaining {
			if ext != nil && reflect.TypeOf(ext).String() == typeName {
				ordered = append(ordered, ext)
				remaining[j] = nil
				break
			}
		}
	}
	// Append any unmatched extensions at the end
	for _, ext := range remaining {
		if ext != nil {
			ordered = append(ordered, ext)
		}
	}

	freshSpec.Extensions = ordered
	return &freshSpec, nil
}

// TCPProfile represents a TCP stack fingerprint
type TCPProfile struct {
	TTL        int `json:"ttl"`
	WindowSize int `json:"window_size"`
	SourcePort int `json:"-"` // New field for custom source port
}

var (
	// Windows TCP profile
	TCPProfileWindows = &TCPProfile{
		TTL:        128,
		WindowSize: 65535,
	}

	// Linux TCP profile
	TCPProfileLinux = &TCPProfile{
		TTL:        64,
		WindowSize: 5840, // often scales
	}

	// macOS TCP profile
	TCPProfileMacOS = &TCPProfile{
		TTL:        64,
		WindowSize: 65535,
	}
)

var AllTCPProfiles = []*TCPProfile{
	TCPProfileWindows,
	TCPProfileLinux,
	TCPProfileMacOS,
}

// GetRandomTCPProfile returns a random TCP profile
func GetRandomTCPProfile() *TCPProfile {
	idx := randomInt(len(AllTCPProfiles))
	return AllTCPProfiles[idx]
}

// ToSpec generates a fixed ClientHelloSpec from the profile's ClientHelloID
func (p *TLSProfile) ToSpec() (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(p.ClientHello)
	if err != nil {
		return nil, err
	}
	return &spec, nil
}
