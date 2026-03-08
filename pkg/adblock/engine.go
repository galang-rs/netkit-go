package adblock

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// Category represents the type of ad or tracker
type Category string

const (
	CatAds       Category = "Ads"
	CatAnalytics Category = "Analytics"
	CatTrackers  Category = "Trackers"
	CatSocial    Category = "Social"
	CatOEM       Category = "OEM"
	CatMix       Category = "Mix"
	CatError     Category = "Error Trackers"
)

// Result contains information about a matched ad/tracker
type Result struct {
	IsAd     bool     `json:"is_ad"`
	Category Category `json:"category"`
	Source   string   `json:"source"`
	Reason   string   `json:"reason"`
}

// Rule defines the interface for ad-blocking rules
type Rule interface {
	Match(url, hostname string) bool
	GetResult() *Result
}

// EasyListRule implements basic EasyList rule matching
type EasyListRule struct {
	Pattern   string
	IsExclude bool
	IsDomain  bool   // ||domain
	Domain    string // Extracted domain from ||domain
	Path      string // Extracted path from ||domain/path
	Result    *Result
}

func (r *EasyListRule) Match(url, hostname string) bool {
	if r.IsDomain {
		// Match domain and subdomains: ||example.com
		domainMatch := false
		if strings.HasSuffix(hostname, r.Domain) {
			if len(hostname) == len(r.Domain) || hostname[len(hostname)-len(r.Domain)-1] == '.' {
				domainMatch = true
			}
		}
		if !domainMatch {
			return false
		}
		// If there's a path requirement
		if r.Path != "" {
			// Find path in URL (after hostname)
			target := url
			if strings.Contains(url, hostname) {
				idx := strings.Index(url, hostname)
				target = url[idx+len(hostname):]
			}
			// Ensure matching works for both /path and path
			target = strings.TrimPrefix(target, "/")
			matchPath := strings.TrimPrefix(r.Path, "/")
			return strings.HasPrefix(target, matchPath)
		}
		return true
	}
	// Keyword matching
	return strings.Contains(url, r.Pattern)
}

func (r *EasyListRule) GetResult() *Result {
	return r.Result
}

// Engine handles high-performance matching
type Engine struct {
	mu          sync.RWMutex
	rules       []Rule
	exemptions  []Rule
	keywordList []keywordEntry // Legacy support
}

// Global engine instance
var defaultEngine *Engine
var once sync.Once

func GetEngine() *Engine {
	once.Do(func() {
		defaultEngine = NewEngine()
		defaultEngine.loadDefaults()
	})
	return defaultEngine
}

func NewEngine() *Engine {
	return &Engine{
		rules:      make([]Rule, 0),
		exemptions: make([]Rule, 0),
	}
}

type keywordEntry struct {
	keyword string
	result  *Result
}

// Match checks if a URL or Hostname matches any ad/tracker pattern
func (e *Engine) Match(url, hostname string) (*Result, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	urlLower := strings.ToLower(url)
	hostLower := strings.ToLower(hostname)

	// If hostname is empty, try to extract it from URL
	if hostLower == "" && urlLower != "" {
		if strings.HasPrefix(urlLower, "http://") {
			parts := strings.SplitN(urlLower[7:], "/", 2)
			hostLower = parts[0]
		} else if strings.HasPrefix(urlLower, "https://") {
			parts := strings.SplitN(urlLower[8:], "/", 2)
			hostLower = parts[0]
		}
	}

	// 1. Check exemptions first (@@ rules)
	for _, rule := range e.exemptions {
		if rule.Match(urlLower, hostLower) {
			return nil, false
		}
	}

	// 2. Structured rules (EasyList)
	for _, rule := range e.rules {
		if rule.Match(urlLower, hostLower) {
			return rule.GetResult(), true
		}
	}

	// 3. Legacy Keyword matching (for backward compatibility during transition)
	searchStr := urlLower
	if searchStr == "" {
		searchStr = hostLower
	}
	for _, entry := range e.keywordList {
		if strings.Contains(searchStr, entry.keyword) {
			return entry.result, true
		}
	}

	return nil, false
}

func (e *Engine) AddDomain(domain string, category Category, source string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	domain = strings.ToLower(domain)
	e.rules = append(e.rules, &EasyListRule{
		Pattern:  domain,
		IsDomain: true,
		Domain:   domain,
		Result: &Result{
			IsAd:     true,
			Category: category,
			Source:   source,
			Reason:   "Matched domain list",
		},
	})
}

func (e *Engine) AddKeyword(keyword string, category Category, source string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.keywordList = append(e.keywordList, keywordEntry{
		keyword: strings.ToLower(keyword),
		result: &Result{
			IsAd:     true,
			Category: category,
			Source:   source,
			Reason:   "Matched keyword pattern",
		},
	})
}

// LoadBlocklist loads rules from an EasyList formatted file
func (e *Engine) LoadBlocklist(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}

		e.ParseRule(line, "File: "+path)
	}
	return scanner.Err()
}

func (e *Engine) ParseRule(line string, source string) {
	isExclude := strings.HasPrefix(line, "@@")
	if isExclude {
		line = line[2:]
	}

	isDomain := strings.HasPrefix(line, "||")
	var domain, path string
	if isDomain {
		line = line[2:]
		// Split by first / to separate domain and path
		idx := strings.Index(line, "/")
		if idx != -1 {
			domain = line[:idx]
			path = strings.TrimSuffix(line[idx:], "^")
		} else {
			domain = line
		}
		// Remove ^ from domain
		domain = strings.TrimSuffix(domain, "^")
	}

	// Remove suffix markers like ^ from pattern if not already handled
	pattern := strings.TrimSuffix(line, "^")

	rule := &EasyListRule{
		Pattern:   strings.ToLower(pattern),
		IsExclude: isExclude,
		IsDomain:  isDomain,
		Domain:    strings.ToLower(domain),
		Path:      strings.ToLower(path),
		Result: &Result{
			IsAd:     true,
			Category: CatAds,
			Source:   source,
			Reason:   "EasyList rule",
		},
	}

	e.mu.Lock()
	if isExclude {
		e.exemptions = append(e.exemptions, rule)
	} else {
		e.rules = append(e.rules, rule)
	}
	e.mu.Unlock()
}

// LoadRemoteBlocklist fetches and parses rules from a remote EasyList URL with local caching
func (e *Engine) LoadRemoteBlocklist(url string) error {
	// 1. Determine cache path
	hash := md5.Sum([]byte(url))
	filename := hex.EncodeToString(hash[:]) + ".txt"
	cacheDir := filepath.Join("cache", "adblock")
	cachePath := filepath.Join(cacheDir, filename)

	// 2. Ensure cache directory exists
	_ = os.MkdirAll(cacheDir, 0755)

	// 3. Check if cache is valid (less than 24h old)
	info, err := os.Stat(cachePath)
	if err == nil {
		if time.Since(info.ModTime()) < 24*time.Hour {
			// Load from cache
			return e.LoadBlocklist(cachePath)
		}
	}

	// 4. Fetch from remote
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		// If download fails but cache exists, fallback to old cache
		if info != nil {
			return e.LoadBlocklist(cachePath)
		}
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if info != nil {
			return e.LoadBlocklist(cachePath)
		}
		return fmt.Errorf("failed to fetch blocklist: %s (status: %d)", url, resp.StatusCode)
	}

	// 5. Save to cache file
	out, err := os.Create(cachePath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	// 6. Load from the newly saved file
	return e.LoadBlocklist(cachePath)
}

func (e *Engine) loadDefaults() {
	// Standard Ad Networks & Pop-under Services
	ads := []string{
		"googleadservices", "googlesyndication", "doubleclick.net", "adservice.google",
		"amazon-adsystem", "adtago.s3", "adcolony", "media.net", "yahooinc.com/adtech",
		"gemini.yahoo", "ads.yahoo", "yandex.ru/metrika", "yandex.ru/adfstat",
		"yandex.net", "yandex.ru/ads", "yandex.ru/clck", "mc.yandex", "offerwall.yandex",
		"extmaps-api.yandex", "an.yandex", "suggest.yandex",
		"unityads.unity3d", "adfox.yandex", "pagead", "partnerads", "afs.google",
		"advice-ads", "taboola.com", "outbrain.com", "adnxs.com", "scorecardresearch.com",
		"popads.net", "popcash.net", "propellerads.com", "clickadu.com", "ad-maven.com",
		"adcash.com", "ybtj.net", "exoclick.com", "popunder", "exdynsrv.com",
		"tpc.googlesyndication.com", "adunit", "img_ad", "simgad", "pro_ads", "rcvlink",
		"jixie", "kg-media", "kompasid", "kompaspunyaharga", "aiml", "jixie.io", "jixie.media",
	}
	for _, a := range ads {
		e.AddKeyword(a, CatAds, "Global Ad List")
	}
	e.AddDomain("tpc.googlesyndication.com", CatAds, "Global Ad List")
	e.AddDomain("doubleclick.net", CatAds, "Global Ad List")
	e.AddDomain("googleadservices.com", CatAds, "Global Ad List")
	e.AddDomain("googlesyndication.com", CatAds, "Global Ad List")
	e.AddDomain("rcvlink.com", CatAds, "Global Ad List")
	e.AddDomain("jixie.io", CatAds, "Jixie Tracker")
	e.AddDomain("jixie.media", CatAds, "Jixie Tracker")

	// Analytics & Trackers (Ghostery-style)
	trackers := []string{
		"google-analytics", "hotjar", "mouseflow", "freshmarketer", "luckyorange",
		"stats.wp.com", "bugsnag", "sentry.io", "getsentry.com", "analytics",
		"tracking", "telemetry", "metrics", "logservice", "crashlytics",
		"amplitude.com", "mixpanel.com", "segment.com", "optimizely.com",
		"popup", "popunder", "interstitial", "overlay", "pro-ads",
		"sentry-cdn", "appmetrica", "iot-logser", "mistat.xiaomi", "sdkconfig.ad",
		"ads.oppomobile", "iadsdk.apple", "2o7.net", "log.fc.yahoo", "udcm.yahoo", "geo.yahoo",
	}
	for _, t := range trackers {
		e.AddKeyword(t, CatAnalytics, "Tracker Blocklist")
	}

	// Social Trackers
	social := []string{
		"pixel.facebook", "an.facebook", "ads-api.twitter", "ads-twitter",
		"ads.linkedin", "pointdrive.linkedin", "ads.pinterest", "log.pinterest",
		"trk.pinterest", "events.redditmedia", "events.reddit", "ads.youtube",
		"byteoversea", "ads-api.tiktok", "analytics.tiktok", "ads.tiktok",
		"business-api.tiktok", "snapchat.com/tr",
	}
	for _, s := range social {
		e.AddKeyword(s, CatSocial, "Social Tracker Blocklist")
	}

	// Spotify Ad-Blocking (Inspired by spotify-adblock)
	spotify := []string{
		"ads-ak-spotify-com.akamaized.net",
		"analytics.spotify.com",
		"adeventtracker.spotify.com",
		"spclient.wg.spotify.com/ads/",
		"spclient.wg.spotify.com/ad-logic/",
		"spclient.wg.spotify.com/v1/ads/",
	}
	for _, s := range spotify {
		e.AddKeyword(s, CatAds, "Spotify Adblock")
	}

	// OEM Telemetry (Mobile/Smartphone)
	e.AddKeyword("realme.com/iot", CatOEM, "Xiaomi/Realme")
	e.AddKeyword("realmemobile.com", CatOEM, "Xiaomi/Realme")
	e.AddKeyword("ad.xiaomi", CatOEM, "Xiaomi/Realme")
	e.AddKeyword("mistat.xiaomi", CatOEM, "Xiaomi/Realme")
	e.AddKeyword("miui.com/tracking", CatOEM, "Xiaomi/Realme")
	e.AddKeyword("adsfs.oppomobile", CatOEM, "Oppo")
	e.AddKeyword("hicloud.com", CatOEM, "Huawei")
	e.AddKeyword("oneplus.net/open", CatOEM, "OnePlus")
	e.AddKeyword("smetrics.samsung", CatOEM, "Samsung")
	e.AddKeyword("nmetrics.samsung", CatOEM, "Samsung")
	e.AddKeyword("samsungads.com", CatOEM, "Samsung")
	e.AddKeyword("metrics.icloud", CatOEM, "Apple")
	e.AddKeyword("adservices.apple", CatOEM, "Apple")

	// Indonesian Regional Blocklist (ABPindo essentials)
	indonesianAds := []string{
		"untd.io", "v-track.id", "klimg.com", "kompas.tv/ads",
		"merdeka.com/ads", "detik.com/ads", "tribunnews.com/ads",
		"liputan6.com/ads", "kaskus.co.id/ads", "bukalapak.com/ads",
		"tokopedia.com/ads", "shopee.co.id/ads", "go-jek.com/ads",
		"grab.com/ads", "traveloka.com/ads", "tiket.com/ads",
	}
	for _, id := range indonesianAds {
		e.AddKeyword(id, CatAds, "Indonesian Ad List")
	}

	// Fetch curated lists remotely for live updates
	go e.LoadRemoteBlocklist("https://easylist.to/easylist/easylist.txt")
	go e.LoadRemoteBlocklist("https://easylist.to/easylist/easyprivacy.txt")
	go e.LoadRemoteBlocklist("https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt")
}

// Common Ad/Sponsored container regex patterns
var adContainerRegex = []*regexp.Regexp{
	// Divs and Sections with ad-related classes or IDs
	regexp.MustCompile(`(?i)<(?:div|section|aside|article|ins)[^>]*class=["'][^"']*(?:sponsored|advertisement|ad-container|ad-slot|ad-wrapper|yt-ad|ad-banner|promoted|popup|modal-ad|overlay|lightbox|interstitial|img_ad|pro_ads|popunder|gpt|adsense|adsbygoogle|dfp|billboard|leaderboard|outbrain|taboola|rcvlink|jixie|wSpec|ads-partner|osmplaceonsite|aiml)[^"']*["'][^>]*>.*?<\/(?:div|section|aside|article|ins)>`),
	regexp.MustCompile(`(?i)<(?:div|section|aside|article|ins)[^>]*id=["'][^"']*(?:sponsored|advertisement|ad-container|ad-slot|ad-wrapper|yt-ad|ad-banner|promoted|popup|modal-ad|overlay|lightbox|interstitial|img_ad|pro_ads|popunder|gpt|adsense|adsbygoogle|dfp|billboard|leaderboard|outbrain|taboola|rcvlink|jixie|google_ads_iframe|wSpec|ads-partner|osmplaceonsite|aiml)[^"']*["'][^>]*>.*?<\/(?:div|section|aside|article|ins)>`),
	// High z-index "covers" or "fixed" overlays
	regexp.MustCompile(`(?i)<(?:div|section|aside|article)[^>]*style=["'][^"']*(?:z-index:\s*(?:2147483647|9999|100000)|position:\s*fixed;[^"']*bottom:\s*0)[^"']*["'][^>]*>.*?<\/(?:div|section|aside|article)>`),
	// Iframes from ad networks (flexible spaces)
	regexp.MustCompile(`(?i)<iframe[^>]*\bsrc\s*=\s*["'][^"']*(?:ads|doubleclick|amazon-adsystem|googlesyndication|adservice|taboola|popads|propeller|adnxs|outbrain|smartadserver|adform|rubiconproject|rcvlink|jixie|google_ads_iframe)[^"']*["'][^>]*>.*?<\/iframe>`),
	// Script tags for ads (flexible spaces)
	regexp.MustCompile(`(?i)<script[^>]*\bsrc\s*=\s*["'][^"']*(?:ads|doubleclick|googlesyndication|adservice|taboola|popads|propeller|adnxs|outbrain|pro_ads|popunder|gpt|adsbygoogle|analytics|metrika|pixel|rcvlink|jixie)[^"']*["'][^>]*>.*?<\/script>`),
	// Targeted inline script blocks (safely anchored to avoid swallowing)
	regexp.MustCompile(`(?i)<script[^>]*>\s*googletag\.cmd\.push[\s\S]*?<\/script>`),
	regexp.MustCompile(`(?i)<script[^>]*>\s*LazyLoadSlot[\s\S]*?<\/script>`),
	regexp.MustCompile(`(?i)<script[^>]*>\s*AIML Article Recommendation[\s\S]*?<\/script>`),
	regexp.MustCompile(`(?i)<script[^>]*>\s*jixie[\s\S]*?<\/script>`),
	// Images with ad markers (flexible spaces)
	regexp.MustCompile(`(?i)<img[^>]*class\s*=\s*["'][^"']*(?:img_ad|ad-image|sponsored-image)[^"']*["'][^>]*>`),
	regexp.MustCompile(`(?i)<img[^>]*\bsrc\s*=\s*["'][^"']*(?:googlesyndication|doubleclick|amazon-adsystem|ads-api|adservice|simgad|ad.doubleclick|tpc.googlesyndication|rcvlink)[^"']*["'][^>]*>`),
	// Ad Links (<a> tags with ad domains) (flexible spaces)
	regexp.MustCompile(`(?i)<a[^>]*\bhref\s*=\s*["'][^"']*(?:googlesyndication|doubleclick|amazon-adsystem|ads-api|adservice|ad.doubleclick|clk.google|adclick|popads|propeller|adnxs|outbrain|pro_ads|popunder|taboola|rcvlink)[^"']*["'][^>]*>.*?<\/a>`),
	// Link tags (dns-prefetch, preconnect, stylesheet) for ad domains (flexible spaces)
	regexp.MustCompile(`(?i)<link[^>]*\bhref\s*=\s*["'][^"']*(?:googlesyndication|doubleclick|amazon-adsystem|ads-api|adservice|ad.doubleclick|tpc.googlesyndication|googletagmanager|google-analytics|rcvlink)[^"']*["'][^>]*>`),
	// Aggressive: Remove ANY attribute containing simgad or tpc.googlesyndication (covers dynamic loads in JS/Data attrs)
	regexp.MustCompile(`(?i)\b(?:src|href|data-src|data-href)\s*=\s*["']https?://[^"']*(?:simgad|tpc\.googlesyndication\.com|rcvlink\.com|doubleclick\.net|googleadservices\.com)[^"']*["']`),
}

// SanitizeHTML is a convenience wrapper for the global engine's sanitizeHTML method.
func SanitizeHTML(body string) string {
	return GetEngine().sanitizeHTML(body)
}

// sanitizeHTML removes common ad containers from the given HTML body.
// It uses a high-performance tokenizer to strip unwanted elements.
func (e *Engine) sanitizeHTML(body string) string {
	if body == "" || len(body) < 10 {
		return body
	}

	z := html.NewTokenizer(strings.NewReader(body))
	var out strings.Builder
	out.Grow(len(body))

	skipDepth := 0

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if z.Err() == io.EOF {
				break
			}
			return body // Fallback to original on error
		}

		token := z.Token()

		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			if e.shouldStripTag(token) {
				if tt == html.StartTagToken {
					skipDepth++
				}
				continue
			}

			// Special case for inline scripts: peek at content
			if token.Data == "script" && tt == html.StartTagToken {
				nextTt := z.Next()
				if nextTt == html.TextToken {
					scriptContent := z.Token().Data
					if e.isAdMarker(scriptContent) {
						// Skip this script and its end tag
						skipDepth++
						// We already moved to text token, so we need to wait for EndTag
						continue
					}
					// If not an ad, we need to output the script tag and the text token
					out.WriteString(token.String())
					out.WriteString(z.Token().String())
					continue
				} else {
					// Not followed by text, output tag and continue normally
					out.WriteString(token.String())
					// Push back the nextTt if it's not text?
					// Actually, the tokenizer state is already advanced.
					// This is a bit tricky with Next().
					// Let's use a simpler approach: if it's a script tag, we always
					// check the next token if it's text.
				}
			}
		}

		if skipDepth > 0 {
			if tt == html.StartTagToken {
				skipDepth++
			} else if tt == html.EndTagToken {
				skipDepth--
			}
			continue
		}

		if tt == html.EndTagToken {
			// Ensure we don't output closing tags for things we skipped
			// skipDepth is already 0 here if we are outputting
		}

		out.WriteString(token.String())
	}

	return out.String()
}

func (e *Engine) shouldStripTag(t html.Token) bool {
	// 1. Identify high-risk tags
	isHighRisk := false
	switch t.Data {
	case "iframe", "ins", "script", "embed", "object":
		isHighRisk = true
	case "div", "section", "aside", "article", "img", "a", "link":
		// These require closer inspection of attributes
	default:
		return false
	}

	// 2. Check attributes for ad markers or blocked URLs
	for _, attr := range t.Attr {
		val := strings.ToLower(attr.Val)
		key := strings.ToLower(attr.Key)

		switch key {
		case "class", "id", "data-ad-client", "data-ad-slot":
			if e.isAdMarker(val) {
				return true
			}
		case "src", "href", "data-src", "data-href":
			// For URLs, check against the adblock engine
			if _, ok := e.Match(val, ""); ok {
				return true
			}
			// Also check if the URL itself contains ad markers
			if e.isAdMarker(val) {
				return true
			}
		case "style":
			// Check for typical ad styles (e.g., fixed overlays with high z-index)
			if strings.Contains(val, "z-index") && (strings.Contains(val, "2147483647") || strings.Contains(val, "99999")) {
				return true
			}
		}
	}

	// 3. Fallback for High-Risk tags that might not have obvious markers
	if isHighRisk {
		// If it's an <ins> or <script> that reached here, check if it's likely an ad
		if t.Data == "ins" || t.Data == "script" {
			for _, attr := range t.Attr {
				if strings.Contains(strings.ToLower(attr.Val), "ads") {
					return true
				}
			}
		}
	}

	return false
}

func (e *Engine) isAdMarker(val string) bool {
	markers := []string{
		"sponsored", "advertisement", "ad-container", "ad-slot", "ad-wrapper",
		"yt-ad", "ad-banner", "promoted", "popup", "adsbygoogle", "dfp",
		"outbrain", "taboola", "rcvlink", "jixie", "aiml", "billboard",
		"leaderboard", "ads-partner", "osmplaceonsite", "gpt", "google_ads_iframe",
		"googletag",
	}
	for _, m := range markers {
		if strings.Contains(val, m) {
			return true
		}
	}
	return false
}
