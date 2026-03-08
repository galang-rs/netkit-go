package network

import (
	"sort"

	http "github.com/bogdanfinn/fhttp"
)

// OrderedHeader represents a header with its order priority
type OrderedHeader struct {
	Key   string
	Value string
	Order int
}

// OrderHeaders reorders HTTP headers according to the specified order
// This is critical for bypassing Cloudflare fingerprinting
func OrderHeaders(req *http.Request, headerOrder []string) {
	if len(headerOrder) == 0 {
		return
	}

	// Create a map of header names to their order priority
	orderMap := make(map[string]int)
	for i, header := range headerOrder {
		orderMap[header] = i
	}

	// Collect all headers with their order
	var orderedHeaders []OrderedHeader
	for key, values := range req.Header {
		order, exists := orderMap[key]
		if !exists {
			// Headers not in the order list go to the end
			order = len(headerOrder) + 1000
		}

		for _, value := range values {
			orderedHeaders = append(orderedHeaders, OrderedHeader{
				Key:   key,
				Value: value,
				Order: order,
			})
		}
	}

	// Sort headers by order
	sort.Slice(orderedHeaders, func(i, j int) bool {
		if orderedHeaders[i].Order != orderedHeaders[j].Order {
			return orderedHeaders[i].Order < orderedHeaders[j].Order
		}
		// If same order, sort alphabetically for consistency
		return orderedHeaders[i].Key < orderedHeaders[j].Key
	})

	// Clear existing headers and re-add in order
	req.Header = http.Header{}
	req.Header[http.HeaderOrderKey] = headerOrder
	for _, h := range orderedHeaders {
		req.Header.Add(h.Key, h.Value)
	}
}

// ApplyBrowserHeaders applies all browser-specific headers with proper ordering
func ApplyBrowserHeaders(req *http.Request, userAgent, acceptLanguage, acceptEncoding, accept string,
	secFetchDest, secFetchMode, secFetchSite, secFetchUser string,
	secChUa, secChUaMobile, secChUaPlatform string,
	headerOrder []string) {

	// Set all headers
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", accept)
	req.Header.Set("Accept-Language", acceptLanguage)
	req.Header.Set("Accept-Encoding", acceptEncoding)

	// Sec-Fetch headers (critical for Cloudflare) - only set if not provided by caller
	if secFetchDest != "" && req.Header.Get("Sec-Fetch-Dest") == "" {
		req.Header.Set("Sec-Fetch-Dest", secFetchDest)
	}
	if secFetchMode != "" && req.Header.Get("Sec-Fetch-Mode") == "" {
		req.Header.Set("Sec-Fetch-Mode", secFetchMode)
	}
	if secFetchSite != "" && req.Header.Get("Sec-Fetch-Site") == "" {
		req.Header.Set("Sec-Fetch-Site", secFetchSite)
	}
	if secFetchUser != "" && req.Header.Get("Sec-Fetch-User") == "" {
		req.Header.Set("Sec-Fetch-User", secFetchUser)
	}

	// sec-ch-ua headers (critical for Chrome-based browsers)
	if secChUa != "" && req.Header.Get("sec-ch-ua") == "" {
		req.Header.Set("sec-ch-ua", secChUa)
	}
	if secChUaMobile != "" && req.Header.Get("sec-ch-ua-mobile") == "" {
		req.Header.Set("sec-ch-ua-mobile", secChUaMobile)
	}
	if secChUaPlatform != "" && req.Header.Get("sec-ch-ua-platform") == "" {
		req.Header.Set("sec-ch-ua-platform", secChUaPlatform)
	}

	// Upgrade-Insecure-Requests for navigation
	if secFetchMode == "navigate" && req.Header.Get("Upgrade-Insecure-Requests") == "" {
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}

	// Cache-Control for navigation
	if secFetchMode == "navigate" && req.Header.Get("Cache-Control") == "" {
		req.Header.Set("Cache-Control", "max-age=0")
	}

	// Apply header ordering
	OrderHeaders(req, headerOrder)
}
