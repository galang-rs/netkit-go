package sandbox

import (
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/proxy"

	"http-interperation/pkg/browser"
	"http-interperation/pkg/network"
)

// Fetch performs an HTTP request using native Go HTTP client with custom TLS
func Fetch(profile *browser.Profile, method, urlStr string, headers map[string]string, body string, proxyAddr string, proxyAuth *proxy.Auth) (*Response, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile cannot be nil")
	}

	// Custom Timeout Logic
	timeoutSeconds := 30
	if val, ok := headers["X-Custom-Timeout"]; ok {
		if val == "0" {
			timeoutSeconds = 0
		} else {
			if sec, err := strconv.Atoi(val); err == nil {
				timeoutSeconds = sec
			}
		}
		delete(headers, "X-Custom-Timeout")
	}

	// Use NewAdaptiveTransport from network package
	transport, err := network.NewAdaptiveTransport(profile.TLSProfile, profile.TCPProfile, proxyAddr, proxyAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to create adaptive transport: %w", err)
	}

	// Create HTTP client
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Create request body reader
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	// Create HTTP request
	req, err := http.NewRequest(method, urlStr, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Apply user headers first
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// 1. Cache-Control (for navigation requests)
	if req.Header.Get("Cache-Control") == "" {
		req.Header.Set("Cache-Control", "max-age=0")
	}

	// 2. Sec-Ch-Ua (Chrome/Edge only)
	if profile.TLSProfile != nil && profile.TLSProfile.SecChUa != "" {
		if req.Header.Get("Sec-Ch-Ua") == "" {
			req.Header.Set("Sec-Ch-Ua", profile.TLSProfile.SecChUa)
		}
		if req.Header.Get("Sec-Ch-Ua-Mobile") == "" {
			req.Header.Set("Sec-Ch-Ua-Mobile", profile.TLSProfile.SecChUaMobile)
		}
		if req.Header.Get("Sec-Ch-Ua-Platform") == "" {
			req.Header.Set("Sec-Ch-Ua-Platform", profile.TLSProfile.SecChUaPlatform)
		}
	}

	// 3. Upgrade-Insecure-Requests
	if req.Header.Get("Sec-Fetch-Mode") != "cors" && req.Header.Get("Upgrade-Insecure-Requests") == "" {
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}

	// 4. User-Agent
	if profile.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}

	// 5. Accept
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	}

	// 6. Sec-Fetch-* headers (MUST be after Accept)
	if req.Header.Get("Sec-Fetch-Site") == "" {
		req.Header.Set("Sec-Fetch-Site", "none")
	}
	if req.Header.Get("Sec-Fetch-Mode") == "" {
		req.Header.Set("Sec-Fetch-Mode", "navigate")
	}

	// Only inject navigation-specific headers if we are indeed in navigate mode
	isNavigate := req.Header.Get("Sec-Fetch-Mode") == "navigate"

	if isNavigate && req.Header.Get("Sec-Fetch-User") == "" {
		req.Header.Set("Sec-Fetch-User", "?1")
	}
	if isNavigate && req.Header.Get("Sec-Fetch-Dest") == "" {
		req.Header.Set("Sec-Fetch-Dest", "document")
	} else if !isNavigate && req.Header.Get("Sec-Fetch-Dest") == "" {
		req.Header.Set("Sec-Fetch-Dest", "empty")
	}

	// 7. Accept-Encoding
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}

	// 8. Accept-Language
	if req.Header.Get("Accept-Language") == "" {
		if profile.Language != "" {
			req.Header.Set("Accept-Language", profile.Language)
		} else {
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		}
	}

	// 9. APPLY HEADER ORDER (Required for fhttp to preserve order)
	if profile.HTTPFingerprint != nil && len(profile.HTTPFingerprint.HeaderOrder) > 0 {
		req.Header[http.HeaderOrderKey] = profile.HTTPFingerprint.HeaderOrder
	}

	// Sync cookies FROM profile.CookieJar TO request
	if profile.CookieJar != nil {
		parsedURL, _ := url.Parse(urlStr)
		netCookies := profile.CookieJar.Cookies(parsedURL)
		if len(netCookies) > 0 {
			for _, c := range netCookies {
				// Convert net/http.Cookie to fhttp.Cookie
				fCookie := &http.Cookie{
					Name:       c.Name,
					Value:      c.Value,
					Path:       c.Path,
					Domain:     c.Domain,
					Expires:    c.Expires,
					RawExpires: c.RawExpires,
					MaxAge:     c.MaxAge,
					Secure:     c.Secure,
					HttpOnly:   c.HttpOnly,
					SameSite:   http.SameSite(c.SameSite),
					Raw:        c.Raw,
					Unparsed:   c.Unparsed,
				}
				req.AddCookie(fCookie)
			}
		}
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Create response
	response := &Response{
		statusCode: resp.StatusCode,
		body:       bodyBytes,
		header:     resp.Header,
		cookies:    resp.Cookies(),
		localAddr:  "local",
		remoteAddr: "remote",
		profile:    profile,
	}

	return response, nil
}

// FetchWithDialer performs an HTTP request using a custom DialContext (e.g. WireGuard TUN direct)
func FetchWithDialer(profile *browser.Profile, dialFunc network.DialContextFunc, method, urlStr string, headers map[string]string, body string) (*Response, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile cannot be nil")
	}

	// Custom Timeout Logic
	timeoutSeconds := 30
	if val, ok := headers["X-Custom-Timeout"]; ok {
		if val == "0" {
			timeoutSeconds = 0
		} else {
			if sec, err := strconv.Atoi(val); err == nil {
				timeoutSeconds = sec
			}
		}
		delete(headers, "X-Custom-Timeout")
	}

	// Use NewAdaptiveTransportWithDialer - no SOCKS proxy needed
	transport, err := network.NewAdaptiveTransportWithDialer(profile.TLSProfile, profile.TCPProfile, dialFunc, "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN transport: %w", err)
	}

	// Create HTTP client
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Create request body reader
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	// Create HTTP request
	req, err := http.NewRequest(method, urlStr, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Apply user headers first
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// 1. Cache-Control
	if req.Header.Get("Cache-Control") == "" {
		req.Header.Set("Cache-Control", "max-age=0")
	}

	// 2. Sec-Ch-Ua
	if profile.TLSProfile != nil && profile.TLSProfile.SecChUa != "" {
		if req.Header.Get("Sec-Ch-Ua") == "" {
			req.Header.Set("Sec-Ch-Ua", profile.TLSProfile.SecChUa)
		}
		if req.Header.Get("Sec-Ch-Ua-Mobile") == "" {
			req.Header.Set("Sec-Ch-Ua-Mobile", profile.TLSProfile.SecChUaMobile)
		}
		if req.Header.Get("Sec-Ch-Ua-Platform") == "" {
			req.Header.Set("Sec-Ch-Ua-Platform", profile.TLSProfile.SecChUaPlatform)
		}
	}

	// 3. Upgrade-Insecure-Requests
	if req.Header.Get("Upgrade-Insecure-Requests") == "" {
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}

	// 4. User-Agent
	if profile.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}

	// 5. Accept
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	}

	// 6. Sec-Fetch-* headers
	if req.Header.Get("Sec-Fetch-Site") == "" {
		req.Header.Set("Sec-Fetch-Site", "none")
	}
	if req.Header.Get("Sec-Fetch-Mode") == "" {
		req.Header.Set("Sec-Fetch-Mode", "navigate")
	}
	if req.Header.Get("Sec-Fetch-User") == "" {
		req.Header.Set("Sec-Fetch-User", "?1")
	}
	if req.Header.Get("Sec-Fetch-Dest") == "" {
		req.Header.Set("Sec-Fetch-Dest", "document")
	}

	// 7. Accept-Encoding
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}

	// 8. Accept-Language
	if req.Header.Get("Accept-Language") == "" {
		if profile.Language != "" {
			req.Header.Set("Accept-Language", profile.Language)
		} else {
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		}
	}

	// 9. Header Order
	if profile.HTTPFingerprint != nil && len(profile.HTTPFingerprint.HeaderOrder) > 0 {
		req.Header[http.HeaderOrderKey] = profile.HTTPFingerprint.HeaderOrder
	}

	// Sync cookies FROM profile.CookieJar TO request
	if profile.CookieJar != nil {
		parsedURL, _ := url.Parse(urlStr)
		netCookies := profile.CookieJar.Cookies(parsedURL)
		if len(netCookies) > 0 {
			for _, c := range netCookies {
				fCookie := &http.Cookie{
					Name:       c.Name,
					Value:      c.Value,
					Path:       c.Path,
					Domain:     c.Domain,
					Expires:    c.Expires,
					RawExpires: c.RawExpires,
					MaxAge:     c.MaxAge,
					Secure:     c.Secure,
					HttpOnly:   c.HttpOnly,
					SameSite:   http.SameSite(c.SameSite),
					Raw:        c.Raw,
					Unparsed:   c.Unparsed,
				}
				req.AddCookie(fCookie)
			}
		}
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Create response
	response := &Response{
		statusCode: resp.StatusCode,
		body:       bodyBytes,
		header:     resp.Header,
		cookies:    resp.Cookies(),
		localAddr:  "local",
		remoteAddr: "remote",
		profile:    profile,
	}

	return response, nil
}

// GenerateNewProfile creates a fresh profile (optionally based on an old one for consistency)
func GenerateNewProfile(oldProfileName string) (*browser.Profile, error) {
	return browser.GenerateFromProfile(oldProfileName)
}

// FetchStream performs an HTTP request and returns the response with an open body stream.
// CALLER MUST CALL resp.Close() when done.
func FetchStream(profile *browser.Profile, method, urlStr string, headers map[string]string, body string, proxyAddr string, proxyAuth *proxy.Auth) (*Response, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile cannot be nil")
	}

	transport, err := network.NewAdaptiveTransport(profile.TLSProfile, profile.TCPProfile, proxyAddr, proxyAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to create adaptive transport: %w", err)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   0, // No timeout for streams
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, urlStr, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" && profile.UserAgent != "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}

	if profile.HTTPFingerprint != nil && len(profile.HTTPFingerprint.HeaderOrder) > 0 {
		req.Header[http.HeaderOrderKey] = profile.HTTPFingerprint.HeaderOrder
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return &Response{
		statusCode: resp.StatusCode,
		bodyStream: resp.Body,
		header:     resp.Header,
		cookies:    resp.Cookies(),
		profile:    profile,
	}, nil
}

// FetchStreamWithDialer is the dialer-compatible version of FetchStream.
func FetchStreamWithDialer(profile *browser.Profile, dialFunc network.DialContextFunc, method, urlStr string, headers map[string]string, body string) (*Response, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile cannot be nil")
	}

	transport, err := network.NewAdaptiveTransportWithDialer(profile.TLSProfile, profile.TCPProfile, dialFunc, "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN transport: %w", err)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   0,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, urlStr, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return &Response{
		statusCode: resp.StatusCode,
		bodyStream: resp.Body,
		header:     resp.Header,
		cookies:    resp.Cookies(),
		profile:    profile,
	}, nil
}
