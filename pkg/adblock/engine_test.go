package adblock

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestSanitizeHTML(t *testing.T) {
	// Read the test HTML file provided by the user
	content, err := os.ReadFile("ads_text.html")
	if err != nil {
		t.Skipf("Skipping: test fixture ads_text.html not found: %v", err)
	}

	html := string(content)

	// Verify ad markers are present BEFORE sanitization
	adMarkers := []string{
		"googlesyndication.com",
		"securepubads.g.doubleclick.net",
		"div-gpt-ad",
		"adsbygoogle",
		"tpc.googlesyndication.com",
		"jixie.media",
		"jixie.io",
		"rcvlink.com",
	}

	foundCount := 0
	for _, marker := range adMarkers {
		if strings.Contains(strings.ToLower(html), strings.ToLower(marker)) {
			foundCount++
		}
	}
	if foundCount == 0 {
		t.Log("Warning: No ad markers found in input file. Test may be invalid.")
	} else {
		t.Logf("Found %d ad markers in input HTML", foundCount)
	}

	// Perform sanitization
	sanitized := SanitizeHTML(html)

	// Verify ad containers and scripts are removed
	// Note: We check specifically for tags that should be stripped by SanitizeHTML regex

	// Doubleclick script tags
	if strings.Contains(sanitized, "securepubads.g.doubleclick.net") {
		t.Error("Sanitized HTML still contains securepubads script link")
	}

	// Googlesyndication links/scripts
	if strings.Contains(sanitized, "googlesyndication.com") {
		t.Error("Sanitized HTML still contains googlesyndication links/scripts")
	}

	// Link tags check
	if strings.Contains(sanitized, "<link") && strings.Contains(sanitized, "googlesyndication") {
		t.Error("Sanitized HTML still contains <link> tags pointing to googlesyndication")
	}

	// Generic ad classes/ids (though these are often in JS strings which we don't strip yet,
	// we only strip the HTML containers)
	removedPatterns := []string{
		"adsbygoogle",
		"dfp",
		"billboard",
	}

	for _, p := range removedPatterns {
		if strings.Contains(sanitized, p) {
			// We only want to alert if it's still in an HTML tag context that should have been removed.
			// However, since SanitizeHTML is aggressive, most simple occurrences should be gone.
			// Let's check for the most common tag patterns.
			if strings.Contains(sanitized, "<ins class=\""+p) || strings.Contains(sanitized, "id=\""+p) || strings.Contains(sanitized, "class=\""+p) {
				t.Errorf("Sanitized HTML still contains ad pattern in tag: %s", p)
			}
		}
	}

	// Verify main content is preserved
	criticalContent := []string{
		"8 Cara Menghilangkan Iklan di HP Android",
		"Google Chrome",
		"Safe Mode",
	}

	// Helper to normalize strings for comparison (regex approach is easier)
	for _, content := range criticalContent {
		// Escape content for regex and allow any whitespace (\s+) between words
		words := strings.Fields(content)
		pattern := "(?i)" + strings.Join(words, `\s+`)
		re := regexp.MustCompile(pattern)

		// Only assert preservation if it was in the original HTML
		if re.MatchString(html) && !re.MatchString(sanitized) {
			t.Errorf("Sanitized HTML missing critical content: %s", content)
			t.Logf("Search pattern was: %s", pattern)
		}
	}

	t.Logf("Sanitization reduced size from %d to %d bytes", len(html), len(sanitized))

	// Write the sanitized output for user review
	err = os.WriteFile("ads_text_sanitized.html", []byte(sanitized), 0644)
	if err != nil {
		t.Errorf("Failed to write sanitized output: %v", err)
	} else {
		t.Log("Successfully generated ads_text_sanitized.html")
	}
}

func TestSanitizeHTML_Basic(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		contains []string
		missing  []string
	}{
		{
			name:     "Remove AdSense",
			input:    `<div>Header</div><ins class="adsbygoogle" style="display:block"></ins><div>Footer</div>`,
			contains: []string{"<div>Header</div>", "<div>Footer</div>"},
			missing:  []string{"adsbygoogle"},
		},
		{
			name:     "Remove Billboard Div",
			input:    `<div>Content</div><div class="billboard-ad">Popup</div>`,
			contains: []string{"<div>Content</div>"},
			missing:  []string{"billboard-ad"},
		},
		{
			name:     "Remove Ad Script",
			input:    `<p>Text</p><script src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script>`,
			contains: []string{"<p>Text</p>"},
			missing:  []string{"googlesyndication"},
		},
		{
			name:     "Remove rcvlink redirection",
			input:    `<div>Main Content</div><a href="https://go.rcvlink.com/go/?bp=123">Click Ad</a>`,
			contains: []string{"<div>Main Content</div>"},
			missing:  []string{"rcvlink", "Click Ad"},
		},
		{
			name:     "Remove tpc.googlesyndication img",
			input:    `<div>Text</div><img src="https://tpc.googlesyndication.com/simgad/9415588245705635251">`,
			contains: []string{"<div>Text</div>"},
			missing:  []string{"googlesyndication", "simgad"},
		},
		{
			name:     "Remove Jixie tracker script",
			input:    `<div>Content</div><script src="https://scripts.jixie.io/jixie.js"></script>`,
			contains: []string{"<div>Content</div>"},
			missing:  []string{"jixie"},
		},
		{
			name:     "Remove inline googletag script",
			input:    `<div>Content</div><script>googletag.cmd.push(function(){});</script>`,
			contains: []string{"<div>Content</div>"},
			missing:  []string{"googletag", "script"},
		},
		{
			name:     "Remove Kompas native ad (wSpec)",
			input:    `<div class="wSpec -aiml">Ad content</div><div>Real content</div>`,
			contains: []string{"<div>Real content</div>"},
			missing:  []string{"wSpec", "Ad content"},
		},
		{
			name:     "Remove google_ads_iframe container",
			input:    `<div id="google_ads_iframe_/123/abc"></div><div>Real content</div>`,
			contains: []string{"<div>Real content</div>"},
			missing:  []string{"google_ads_iframe"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := SanitizeHTML(tc.input)
			for _, c := range tc.contains {
				if !strings.Contains(output, c) {
					t.Errorf("Expected content missing: %s", c)
				}
			}
			for _, m := range tc.missing {
				if strings.Contains(output, m) {
					t.Errorf("Unwanted content remains: %s", m)
				}
			}
		})
	}
}

func TestEngine_Match(t *testing.T) {
	e := GetEngine()
	fmt.Printf("--- DEBUG: Engine Rules: %d rules, %d keywords ---\n", len(e.rules), len(e.keywordList))

	tests := []struct {
		url      string
		hostname string
		isAd     bool
	}{
		{"https://tpc.googlesyndication.com/simgad/123", "tpc.googlesyndication.com", true},
		{"https://doubleclick.net/adj/test", "doubleclick.net", true},
		{"https://google.com/search?q=test", "google.com", false},
		{"http://example.com/adunit/js", "example.com", true},
		{"https://go.rcvlink.com/go/?bp=test", "go.rcvlink.com", true},
		{"https://tpc.googlesyndication.com/simgad/123", "tpc.googlesyndication.com", true},
		{"https://scripts.jixie.io/jixie.js", "scripts.jixie.io", true},
		{"https://aiml.kompas.com/rec", "aiml.kompas.com", true},
	}

	for _, tt := range tests {
		res, ok := e.Match(tt.url, tt.hostname)
		if ok != tt.isAd {
			fmt.Printf("--- FAIL Match: URL=%q Host=%q | got ok=%v, want ok=%v (res: %v) ---\n", tt.url, tt.hostname, ok, tt.isAd, res)
			t.Errorf("FAIL Match: URL=%q Host=%q | got ok=%v, want ok=%v (res: %v)", tt.url, tt.hostname, ok, tt.isAd, res)
		} else {
			fmt.Printf("--- PASS Match: URL=%q -> ok=%v ---\n", tt.url, ok)
			t.Logf("PASS Match: URL=%q -> ok=%v", tt.url, ok)
		}
	}
}

func TestEngine_EasyList(t *testing.T) {
	e := NewEngine()

	// 1. Domain rule
	e.ParseRule("||doubleclick.net^", "Test List")
	// 2. Exception rule
	e.ParseRule("@@||googleadservices.com^", "Test List")
	// 3. Keyword rule
	e.ParseRule("ads-script", "Test List")

	tests := []struct {
		url      string
		hostname string
		isAd     bool
	}{
		{"https://doubleclick.net/js", "doubleclick.net", true},
		{"https://sub.doubleclick.net/js", "sub.doubleclick.net", true},
		{"https://googleadservices.com/pixel", "googleadservices.com", false}, // Exception
		{"https://example.com/ads-script.js", "example.com", true},
		{"https://example.com/normal.js", "example.com", false},
	}

	for _, tt := range tests {
		_, ok := e.Match(tt.url, tt.hostname)
		if ok != tt.isAd {
			t.Errorf("Match(%q, %q) = %v; want %v", tt.url, tt.hostname, ok, tt.isAd)
		}
	}
}

func TestEngine_LoadRemoteBlocklist(t *testing.T) {
	// Skip if no internet
	e := NewEngine()
	// Using a small and stable EasyList-compatible URL (ABPindo as researched)
	url := "https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt"
	err := e.LoadRemoteBlocklist(url)
	if err != nil {
		t.Skipf("Network error or URL inaccessible: %v", err)
	}

	// Verify at least some rules are loaded
	if len(e.rules) == 0 && len(e.exemptions) == 0 {
		t.Errorf("No rules loaded from %s", url)
	}

	// Verify cache directory exists after load
	cacheDir := filepath.Join("cache", "adblock")
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		t.Errorf("Cache directory %s was not created", cacheDir)
	}
}

func TestEngine_LoadBlocklist(t *testing.T) {
	// Create a dummy EasyList file
	content := `! Title: Dummy List
[Adblock Plus 2.0]
||adnetwork.com^
@@||adnetwork.com/trusted^
/ads/banner.jpg
`
	tmpfile, err := os.CreateTemp("", "easylist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	e := NewEngine()
	if err := e.LoadBlocklist(tmpfile.Name()); err != nil {
		t.Fatalf("LoadBlocklist failed: %v", err)
	}

	tests := []struct {
		url      string
		hostname string
		isAd     bool
	}{
		{"https://adnetwork.com/script.js", "adnetwork.com", true},
		{"https://adnetwork.com/trusted/script.js", "adnetwork.com", false}, // Exception
		{"https://example.com/ads/banner.jpg", "example.com", true},
	}

	for _, tt := range tests {
		_, ok := e.Match(tt.url, tt.hostname)
		if ok != tt.isAd {
			t.Errorf("Match(%q, %q) = %v; want %v", tt.url, tt.hostname, ok, tt.isAd)
		}
	}
}
