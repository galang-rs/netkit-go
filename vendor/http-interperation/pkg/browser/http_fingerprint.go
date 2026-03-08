package browser

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// HTTPFingerprint represents HTTP/1.1 and HTTP/2 fingerprint parameters
type HTTPFingerprint struct {
	// HTTP/2 Settings
	HeaderTableSize      uint32 `json:"h2_header_table_size"`
	EnablePush           uint32 `json:"h2_enable_push"`
	MaxConcurrentStreams uint32 `json:"h2_max_concurrent_streams"`
	InitialWindowSize    uint32 `json:"h2_initial_window_size"`
	MaxFrameSize         uint32 `json:"h2_max_frame_size"`
	MaxHeaderListSize    uint32 `json:"h2_max_header_list_size"`

	// HTTP/2 Window Update
	WindowUpdateIncrement uint32 `json:"h2_window_update"`

	// HTTP/2 Priority
	StreamWeight uint8  `json:"h2_stream_weight"`
	StreamDep    uint32 `json:"h2_stream_dep"`
	Exclusive    bool   `json:"h2_exclusive"`

	// HTTP/1.1 Headers order
	HeaderOrder []string `json:"header_order"`

	// Accept headers
	Accept         string `json:"accept"`
	AcceptLanguage string `json:"accept_language"`
	AcceptEncoding string `json:"accept_encoding"`

	// Connection headers
	Connection string `json:"connection"`
	KeepAlive  string `json:"keep_alive"`

	// Cache headers
	CacheControl string `json:"cache_control"`
	Pragma       string `json:"pragma"`

	// Security headers
	SecFetchDest    string `json:"sec_fetch_dest"`
	SecFetchMode    string `json:"sec_fetch_mode"`
	SecFetchSite    string `json:"sec_fetch_site"`
	SecFetchUser    string `json:"sec_fetch_user"`
	SecChUa         string `json:"sec_ch_ua"`
	SecChUaMobile   string `json:"sec_ch_ua_mobile"`
	SecChUaPlatform string `json:"sec_ch_ua_platform"`
}

// Pre-defined HTTP/2 Settings fingerprints based on real browsers
var (
	// Chrome HTTP/2 fingerprint (Version 120+)
	http2Chrome = HTTP2Settings{
		HeaderTableSize:      65536,
		EnablePush:           0,
		MaxConcurrentStreams: 1000,
		InitialWindowSize:    6291456,
		MaxFrameSize:         16384,
		MaxHeaderListSize:    262144,
		WindowUpdate:         15728640,
		StreamWeight:         255,
	}

	// Firefox HTTP/2 fingerprint (Version 117+)
	http2Firefox = HTTP2Settings{
		HeaderTableSize:      65536,
		EnablePush:           0, // Firefox disabled Push by default recently
		MaxConcurrentStreams: 128,
		InitialWindowSize:    131072,
		MaxFrameSize:         16384,
		MaxHeaderListSize:    0,
		WindowUpdate:         12517377,
		StreamWeight:         201, // Priority weight often 201 for Firefox
	}

	// Safari HTTP/2 fingerprint
	http2Safari = HTTP2Settings{
		HeaderTableSize:      4096,
		EnablePush:           1,
		MaxConcurrentStreams: 100,
		InitialWindowSize:    2097152,
		MaxFrameSize:         16384,
		MaxHeaderListSize:    0,
		WindowUpdate:         10485760,
		StreamWeight:         255,
	}

	// Edge HTTP/2 fingerprint (Chrome-based)
	http2Edge = HTTP2Settings{
		HeaderTableSize:      65536,
		EnablePush:           0,
		MaxConcurrentStreams: 1000,
		InitialWindowSize:    6291456,
		MaxFrameSize:         16384,
		MaxHeaderListSize:    262144,
		WindowUpdate:         15728640,
		StreamWeight:         255,
	}
)

// HTTP2Settings contains HTTP/2 SETTINGS frame parameters
type HTTP2Settings struct {
	HeaderTableSize      uint32
	EnablePush           uint32
	MaxConcurrentStreams uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	MaxHeaderListSize    uint32
	WindowUpdate         uint32
	StreamWeight         uint8
}

// HTTP header orders for different browsers
var (
	chromeHeaderOrder = []string{
		"Host",
		"Connection",
		"Cache-Control",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"Upgrade-Insecure-Requests",
		"User-Agent",
		"Accept",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Sec-Fetch-User",
		"Sec-Fetch-Dest",
		"Accept-Encoding",
		"Accept-Language",
	}

	firefoxHeaderOrder = []string{
		"Host",
		"User-Agent",
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
		"Connection",
		"Upgrade-Insecure-Requests",
		"Sec-Fetch-Dest",
		"Sec-Fetch-Mode",
		"Sec-Fetch-Site",
		"Sec-Fetch-User",
		"Cache-Control",
	}

	safariHeaderOrder = []string{
		"Host",
		"Accept",
		"Sec-Fetch-Site",
		"Accept-Language",
		"Sec-Fetch-Mode",
		"Accept-Encoding",
		"Sec-Fetch-Dest",
		"User-Agent",
	}
)

// Accept-Language variations
var acceptLanguages = []string{
	"en-US,en;q=0.9",
	"en-US,en;q=0.9,id;q=0.8",
	"en-GB,en-US;q=0.9,en;q=0.8",
	"en-US,en;q=0.9,de;q=0.8",
	"en-US,en;q=0.9,fr;q=0.8",
	"en-US,en;q=0.9,es;q=0.8",
	"en-US,en;q=0.9,ja;q=0.8",
	"en-US,en;q=0.9,zh-CN;q=0.8",
	"en,en-US;q=0.9",
	"en-US,en;q=0.8",
}

// Accept-Encoding variations
var acceptEncodings = []string{
	"gzip, deflate, br",
	"gzip, deflate, br, zstd",
	"gzip, deflate",
	"br, gzip, deflate",
	"gzip, deflate, br, identity",
}

// sec-ch-ua variations for Chrome-based browsers
var secChUaVariations = []string{
	`"Chromium";v="120", "Google Chrome";v="120", "Not A(Brand";v="99"`,
	`"Chromium";v="121", "Google Chrome";v="121", "Not=A?Brand";v="8"`,
	`"Chromium";v="119", "Google Chrome";v="119", "Not?A_Brand";v="24"`,
	`"Microsoft Edge";v="120", "Chromium";v="120", "Not A(Brand";v="99"`,
	`"Microsoft Edge";v="121", "Chromium";v="121", "Not=A?Brand";v="8"`,
}

// NewHTTPFingerprint creates a new HTTP fingerprint based on browser type
func NewHTTPFingerprint(browserType string) *HTTPFingerprint {
	fp := &HTTPFingerprint{}

	switch {
	case strings.Contains(browserType, "Chrome"):
		fp.applyChrome()
	case strings.Contains(browserType, "Firefox"):
		fp.applyFirefox()
	case strings.Contains(browserType, "Safari"):
		fp.applySafari()
	case strings.Contains(browserType, "Edge"):
		fp.applyEdge()
	default:
		fp.applyChrome() // Default to Chrome
	}

	// Randomize some values for uniqueness
	fp.randomize()

	return fp
}

func (fp *HTTPFingerprint) applyChrome() {
	fp.HeaderTableSize = http2Chrome.HeaderTableSize
	fp.EnablePush = http2Chrome.EnablePush
	fp.MaxConcurrentStreams = http2Chrome.MaxConcurrentStreams
	fp.InitialWindowSize = http2Chrome.InitialWindowSize
	fp.MaxFrameSize = http2Chrome.MaxFrameSize
	fp.MaxHeaderListSize = http2Chrome.MaxHeaderListSize
	fp.WindowUpdateIncrement = http2Chrome.WindowUpdate
	fp.StreamWeight = http2Chrome.StreamWeight

	fp.HeaderOrder = chromeHeaderOrder
	fp.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	fp.AcceptEncoding = "gzip, deflate, br, zstd"
	fp.Connection = "keep-alive"
	fp.CacheControl = "max-age=0"

	fp.SecFetchDest = "document"
	fp.SecFetchMode = "navigate"
	fp.SecFetchSite = "none"
	fp.SecFetchUser = "?1"
	fp.SecChUaMobile = "?0"
	fp.SecChUaPlatform = `"Windows"`
}

func (fp *HTTPFingerprint) applyFirefox() {
	fp.HeaderTableSize = http2Firefox.HeaderTableSize
	fp.EnablePush = http2Firefox.EnablePush
	fp.MaxConcurrentStreams = http2Firefox.MaxConcurrentStreams
	fp.InitialWindowSize = http2Firefox.InitialWindowSize
	fp.MaxFrameSize = http2Firefox.MaxFrameSize
	fp.MaxHeaderListSize = http2Firefox.MaxHeaderListSize
	fp.WindowUpdateIncrement = http2Firefox.WindowUpdate
	fp.StreamWeight = http2Firefox.StreamWeight

	fp.HeaderOrder = firefoxHeaderOrder
	fp.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
	fp.AcceptEncoding = "gzip, deflate"
	fp.Connection = "keep-alive"
	fp.CacheControl = "no-cache"
	fp.Pragma = "no-cache"

	fp.SecFetchDest = "document"
	fp.SecFetchMode = "navigate"
	fp.SecFetchSite = "none"
	fp.SecFetchUser = "?1"
}

func (fp *HTTPFingerprint) applySafari() {
	fp.HeaderTableSize = http2Safari.HeaderTableSize
	fp.EnablePush = http2Safari.EnablePush
	fp.MaxConcurrentStreams = http2Safari.MaxConcurrentStreams
	fp.InitialWindowSize = http2Safari.InitialWindowSize
	fp.MaxFrameSize = http2Safari.MaxFrameSize
	fp.MaxHeaderListSize = http2Safari.MaxHeaderListSize
	fp.WindowUpdateIncrement = http2Safari.WindowUpdate
	fp.StreamWeight = http2Safari.StreamWeight

	fp.HeaderOrder = safariHeaderOrder
	fp.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	fp.AcceptEncoding = "gzip, deflate"
	fp.Connection = "keep-alive"

	fp.SecFetchDest = "document"
	fp.SecFetchMode = "navigate"
	fp.SecFetchSite = "none"
}

func (fp *HTTPFingerprint) applyEdge() {
	fp.HeaderTableSize = http2Edge.HeaderTableSize
	fp.EnablePush = http2Edge.EnablePush
	fp.MaxConcurrentStreams = http2Edge.MaxConcurrentStreams
	fp.InitialWindowSize = http2Edge.InitialWindowSize
	fp.MaxFrameSize = http2Edge.MaxFrameSize
	fp.MaxHeaderListSize = http2Edge.MaxHeaderListSize
	fp.WindowUpdateIncrement = http2Edge.WindowUpdate
	fp.StreamWeight = http2Edge.StreamWeight

	fp.HeaderOrder = chromeHeaderOrder
	fp.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	fp.AcceptEncoding = "gzip, deflate, br, zstd"
	fp.Connection = "keep-alive"
	fp.CacheControl = "max-age=0"

	fp.SecFetchDest = "document"
	fp.SecFetchMode = "navigate"
	fp.SecFetchSite = "none"
	fp.SecFetchUser = "?1"
	fp.SecChUaMobile = "?0"
	fp.SecChUaPlatform = `"Windows"`
}

// randomInt64Range returns a random int64 between min and max (inclusive)
func randomInt64Range(min, max int64) int64 {
	if max <= min {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max-min+1))
	if err != nil {
		return min
	}
	return n.Int64() + min
}

// randomInt returns a random integer between 0 and max (exclusive)
// Duplicated from profile.go/tls_profiles.go to keep package usage simple if needed,
// but let's assume we can use the one from math/rand for internal logic or copy it.
// http_fingerprint.go used `randomInt`.
// I will rewrite randomInt here.

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

func (fp *HTTPFingerprint) randomize() {
	// Randomize Accept-Language
	fp.AcceptLanguage = acceptLanguages[randomInt(len(acceptLanguages))]

	// Small variations in InitialWindowSize (±10%)
	variation := int64(float64(fp.InitialWindowSize) * 0.1)
	fp.InitialWindowSize = uint32(int64(fp.InitialWindowSize) + randomInt64Range(-variation, variation))

	// Small variations in WindowUpdate (±5%)
	variation = int64(float64(fp.WindowUpdateIncrement) * 0.05)
	fp.WindowUpdateIncrement = uint32(int64(fp.WindowUpdateIncrement) + randomInt64Range(-variation, variation))

	// NOTE: sec-ch-ua is now generated from User-Agent in sandbox.go
	// to ensure version consistency - do NOT randomize it here
}

// String returns a fingerprint signature
func (fp *HTTPFingerprint) String() string {
	return fmt.Sprintf("H2[HTS:%d,IWS:%d,WU:%d,SW:%d]",
		fp.HeaderTableSize, fp.InitialWindowSize, fp.WindowUpdateIncrement, fp.StreamWeight)
}

// GetHTTP2Fingerprint returns Akamai-style HTTP/2 fingerprint
func (fp *HTTPFingerprint) GetHTTP2Fingerprint() string {
	// Format: SETTINGS order|Window Update|Stream Priority
	// Example: 1:65536;2:0;3:1000;4:6291456;6:262144|15728640|0:1:256
	return fmt.Sprintf("1:%d;2:%d;3:%d;4:%d;5:%d;6:%d|%d|0:1:%d",
		fp.HeaderTableSize,
		fp.EnablePush,
		fp.MaxConcurrentStreams,
		fp.InitialWindowSize,
		fp.MaxFrameSize,
		fp.MaxHeaderListSize,
		fp.WindowUpdateIncrement,
		fp.StreamWeight,
	)
}
