package adblock

import (
	"strings"
	"testing"
)

func TestAdBlockReal_ProductFlow(t *testing.T) {
	engine := NewEngine()
	engine.AddDomain("doubleclick.net", CatAds, "TestList")
	engine.AddKeyword("sponsored", CatAds, "TestList")

	// 1. Test Domain Matching
	res, ok := engine.Match("https://doubleclick.net/ad.js", "doubleclick.net")
	if !ok || !res.IsAd {
		t.Errorf("Expected doubleclick.net to be blocked")
	}
	if res.Category != CatAds {
		t.Errorf("Expected category Ads, got %s", res.Category)
	}

	// 2. Test Keyword Matching
	res, ok = engine.Match("https://example.com/sponsored-content", "example.com")
	if !ok || !res.IsAd {
		t.Errorf("Expected URL with 'sponsored' to be blocked")
	}

	// 3. Test HTML Sanitization (Real-world scenario)
	html := `
<html>
	<body>
		<div class="content">Real Info</div>
		<div class="advertisement">Buy This Now!</div>
		<iframe src="https://ads.doubleclick.net"></iframe>
		<footer>Footer</footer>
	</body>
</html>`

	sanitized := engine.sanitizeHTML(html)
	if strings.Contains(sanitized, "advertisement") {
		t.Errorf("Sanitization failed to remove advertisement div")
	}
	if strings.Contains(sanitized, "iframe") {
		t.Errorf("Sanitization failed to remove ad iframe")
	}
	if !strings.Contains(sanitized, "Real Info") {
		t.Errorf("Sanitization accidentally removed real content")
	}

	t.Logf("AdBlock verified! HTML shrunk from %d to %d bytes", len(html), len(sanitized))
}
