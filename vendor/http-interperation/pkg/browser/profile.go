package browser

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"http-interperation/pkg/network"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	"github.com/google/uuid"
)

// Profile represents an isolated HTTP client with unique identity
type Profile struct {
	ID              string                 `json:"id"`
	NetworkID       string                 `json:"network_id"` // SHA256 hash of ID for network identification
	TLSProfile      *network.TLSProfile    `json:"tls_profile"`
	TCPProfile      *network.TCPProfile    `json:"tcp_profile"`
	TLSExtensions   *network.TLSExtensions `json:"tls_extensions"`
	HTTPFingerprint *HTTPFingerprint       `json:"http_fingerprint"`
	DeviceID        string                 `json:"device_id"`
	SessionID       string                 `json:"session_id"`
	UserAgent       string                 `json:"user_agent"`
	Platform        string                 `json:"platform"`
	Vendor          string                 `json:"vendor"`
	ScreenWidth     int                    `json:"screen_width"`
	ScreenHeight    int                    `json:"screen_height"`
	HeapSizeLimit   int                    `json:"heap_size_limit"`
	Concurrency     int                    `json:"concurrency"`
	ColorDepth      int                    `json:"color_depth"`
	PixelRatio      float64                `json:"pixel_ratio"`
	Timezone        string                 `json:"timezone"`
	Language        string                 `json:"language"`
	Languages       []string               `json:"languages"`
	DoNotTrack      string                 `json:"do_not_track"`
	CookieEnabled   bool                   `json:"cookie_enabled"`
	CreatedAt       time.Time              `json:"created_at"`

	// CookieJar stores persistence cookies for this profile
	CookieJar http.CookieJar `json:"-"`
}

// Generate creates a new randomized profile
func Generate() (*Profile, error) {
	return GenerateFromProfile("")
}

// GenerateFromProfile creates a profile using a specific TLS profile name
func GenerateFromProfile(name string) (*Profile, error) {
	var randomProfile *network.TLSProfile
	var err error

	if name != "" {
		randomProfile, err = network.GetProfileByName(name)
		if err != nil {
			// fmt.Printf("[DEBUG] GenerateFromProfile: Profile %s not found, falling back to random\n", name)
			randomProfile = nil
		}
	}

	if randomProfile == nil {
		randomProfile = network.GetRandomProfile()
	}

	// Step 2: Use the User-Agent FROM the TLS profile to ensure consistency
	userAgent := randomProfile.UserAgent

	// Step 3: Determine OS from User-Agent for TCP profile consistency
	var tcpProfile *network.TCPProfile
	if strings.Contains(userAgent, "Windows") {
		tcpProfile = network.TCPProfileWindows
	} else if strings.Contains(userAgent, "Macintosh") || strings.Contains(userAgent, "Mac OS") {
		tcpProfile = network.TCPProfileMacOS
	} else if strings.Contains(userAgent, "Linux") || strings.Contains(userAgent, "Android") {
		tcpProfile = network.TCPProfileLinux
	} else if strings.Contains(userAgent, "iPhone") || strings.Contains(userAgent, "iPad") {
		tcpProfile = network.TCPProfileMacOS
	} else {
		tcpProfile = network.TCPProfileWindows
	}

	// Step 4: Create profile with CONSISTENT values
	tlsProfile := &network.TLSProfile{
		Name:            randomProfile.Name,
		ClientHello:     randomProfile.ClientHello,
		UserAgent:       userAgent,
		Platform:        randomProfile.Platform,
		Vendor:          randomProfile.Vendor,
		SecChUa:         randomProfile.SecChUa,
		SecChUaMobile:   randomProfile.SecChUaMobile,
		SecChUaPlatform: randomProfile.SecChUaPlatform,
	}

	// Step 4.5: Pin the spec for JA3 consistency if valid
	if spec, err := tlsProfile.ToSpec(); err == nil {
		tlsProfile.Spec = spec
	}

	// Step 5: Generate sec-ch-ua from User-Agent version for Chrome-based browsers
	if strings.Contains(userAgent, "Chrome/") {
		tlsProfile.SecChUa = GenerateSecChUaFromUA(userAgent)
	}

	// Create HTTP fingerprint based on browser type
	httpFP := NewHTTPFingerprint(tlsProfile.Name)

	// Create TLS extensions with ECH support
	tlsExt := network.NewTLSExtensions(tlsProfile.Name)

	// Get random screen size
	screenIdx := randomInt(len(ScreenSizes))
	screen := ScreenSizes[screenIdx]

	// Get random heap size
	heapIdx := randomInt(len(HeapSizeLimits))
	heapSize := HeapSizeLimits[heapIdx]
	concurrency := HeapToConcurrency[heapSize]

	// Get random color depth
	colorDepths := []int{24, 32}
	colorDepth := colorDepths[randomInt(len(colorDepths))]

	// Get random pixel ratio
	pixelRatios := []float64{1.0, 1.25, 1.5, 2.0}
	pixelRatio := pixelRatios[randomInt(len(pixelRatios))]

	// Get random timezone
	timezones := []string{
		"America/New_York", "America/Los_Angeles", "America/Chicago",
		"Europe/London", "Europe/Paris", "Asia/Tokyo", "Asia/Singapore",
	}
	timezone := timezones[randomInt(len(timezones))]

	// Get random DNT setting
	dntOptions := []string{"1", "0", "null"}
	doNotTrack := dntOptions[randomInt(len(dntOptions))]

	id := uuid.New().String()
	hash := sha256.Sum256([]byte(id))
	networkID := hex.EncodeToString(hash[:])

	profile := &Profile{
		ID:              id,
		NetworkID:       networkID,
		TLSProfile:      tlsProfile,
		TCPProfile:      tcpProfile,
		TLSExtensions:   tlsExt,
		HTTPFingerprint: httpFP,
		DeviceID:        uuid.New().String(),
		SessionID:       uuid.New().String(),
		UserAgent:       userAgent,
		Platform:        tlsProfile.Platform,
		Vendor:          tlsProfile.Vendor,
		ScreenWidth:     screen[0],
		ScreenHeight:    screen[1],
		HeapSizeLimit:   heapSize,
		Concurrency:     concurrency,
		ColorDepth:      colorDepth,
		PixelRatio:      pixelRatio,
		Timezone:        timezone,
		Language:        httpFP.AcceptLanguage,
		Languages:       []string{"en-US", "en"},
		DoNotTrack:      doNotTrack,
		CookieEnabled:   true,
		CreatedAt:       time.Now(),
		CookieJar:       nil, // Will be initialized below
	}

	// Initialize CookieJar
	jar, _ := cookiejar.New(nil)
	profile.CookieJar = jar

	return profile, nil
}

// Repair ensures the profile is consistent and fixes common issues from serialization
func (p *Profile) Repair() {
	if p.TLSProfile == nil {
		return
	}

	// Fix empty ClientHelloID (always empty when loaded from JSON as it is ignored)
	// We restore it from the Name which is saved in the JSON
	if proto, err := network.GetProfileByName(p.TLSProfile.Name); err == nil {
		p.TLSProfile.ClientHello = proto.ClientHello
	}

	// Re-cache Spec if missing
	if p.TLSProfile.Spec == nil {
		if spec, err := p.TLSProfile.ToSpec(); err == nil {
			p.TLSProfile.Spec = spec
		}
	}

	// Initialize CookieJar if missing (not persisted in JSON)
	if p.CookieJar == nil {
		if jar, err := cookiejar.New(nil); err == nil {
			p.CookieJar = jar
		}
	}
}
