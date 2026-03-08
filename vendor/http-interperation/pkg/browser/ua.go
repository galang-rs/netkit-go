package browser

import "strings"

// GenerateSecChUaFromUA extracts Chrome version from User-Agent and generates matching sec-ch-ua
// Used by profile.go
func GenerateSecChUaFromUA(userAgent string) string {
	// Extract Chrome version from User-Agent
	// Format: Chrome/120.0.0.0 -> extract "120"
	var version string
	if idx := strings.Index(userAgent, "Chrome/"); idx != -1 {
		versionStart := idx + 7
		versionEnd := versionStart
		for versionEnd < len(userAgent) && userAgent[versionEnd] != '.' && userAgent[versionEnd] != ' ' {
			versionEnd++
		}
		version = userAgent[versionStart:versionEnd]
	}

	if version == "" {
		version = "120" // Fallback
	}

	// Check if it's Edge
	if strings.Contains(userAgent, "Edg/") {
		return `"Microsoft Edge";v="` + version + `", "Chromium";v="` + version + `", "Not_A Brand";v="8"`
	}

	// Regular Chrome
	return `"Chromium";v="` + version + `", "Google Chrome";v="` + version + `", "Not_A Brand";v="8"`
}
