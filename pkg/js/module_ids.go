package js

import (
	"bytes"
	"regexp"
	"strings"
	"sync"
)

// Signature represents an IDS signature rule.
type Signature struct {
	ID      string
	Name    string
	Pattern []byte // byte pattern to match
	Regex   string // regex pattern (alternative to byte pattern)
	Action  string // "alert", "drop", "log"
}

// signatureEngine manages IDS signatures.
type signatureEngine struct {
	mu         sync.RWMutex
	signatures []*Signature
}

var globalSignatureEngine = &signatureEngine{}

// RegisterIDSModule injects ctx.IDS into the JS context.
func RegisterIDSModule(jsCtx map[string]interface{}) {
	se := globalSignatureEngine

	jsCtx["IDS"] = map[string]interface{}{
		// PatternMatch checks if payload contains a byte pattern.
		"PatternMatch": func(payload, pattern []byte) bool {
			return bytes.Contains(payload, pattern)
		},

		// PatternMatchString checks if payload contains a string pattern.
		"PatternMatchString": func(payload []byte, pattern string) bool {
			return bytes.Contains(payload, []byte(pattern))
		},

		// RegexMatch checks if payload matches a regex pattern.
		"RegexMatch": func(payload []byte, pattern string) (bool, error) {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false, err
			}
			return re.Match(payload), nil
		},

		// RegexFind returns all regex matches in payload.
		"RegexFind": func(payload []byte, pattern string) ([]string, error) {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, err
			}
			matches := re.FindAllString(string(payload), -1)
			return matches, nil
		},

		// RegexReplace replaces regex matches in payload.
		"RegexReplace": func(payload []byte, pattern, replacement string) ([]byte, error) {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, err
			}
			return re.ReplaceAll(payload, []byte(replacement)), nil
		},

		// AddSignature adds a new signature to the engine.
		"AddSignature": func(id, name string, pattern []byte, regexPattern, action string) {
			se.mu.Lock()
			defer se.mu.Unlock()
			se.signatures = append(se.signatures, &Signature{
				ID:      id,
				Name:    name,
				Pattern: pattern,
				Regex:   regexPattern,
				Action:  action,
			})
		},

		// RemoveSignature removes a signature by ID.
		"RemoveSignature": func(id string) {
			se.mu.Lock()
			defer se.mu.Unlock()
			for i, sig := range se.signatures {
				if sig.ID == id {
					se.signatures = append(se.signatures[:i], se.signatures[i+1:]...)
					break
				}
			}
		},

		// ScanPayload checks payload against all signatures.
		// Returns list of matching signature IDs and their actions.
		"ScanPayload": func(payload []byte) []map[string]interface{} {
			se.mu.RLock()
			defer se.mu.RUnlock()
			var matches []map[string]interface{}
			for _, sig := range se.signatures {
				matched := false
				if len(sig.Pattern) > 0 {
					matched = bytes.Contains(payload, sig.Pattern)
				}
				if !matched && sig.Regex != "" {
					re, err := regexp.Compile(sig.Regex)
					if err == nil {
						matched = re.Match(payload)
					}
				}
				if matched {
					matches = append(matches, map[string]interface{}{
						"id":     sig.ID,
						"name":   sig.Name,
						"action": sig.Action,
					})
				}
			}
			return matches
		},

		// ListSignatures returns all loaded signatures.
		"ListSignatures": func() []map[string]interface{} {
			se.mu.RLock()
			defer se.mu.RUnlock()
			var result []map[string]interface{}
			for _, sig := range se.signatures {
				result = append(result, map[string]interface{}{
					"id":     sig.ID,
					"name":   sig.Name,
					"action": sig.Action,
				})
			}
			return result
		},

		// ClearSignatures removes all signatures.
		"ClearSignatures": func() {
			se.mu.Lock()
			se.signatures = nil
			se.mu.Unlock()
		},

		// ContainsAny checks if payload contains any of the given patterns.
		"ContainsAny": func(payload []byte, patterns []interface{}) bool {
			for _, p := range patterns {
				switch v := p.(type) {
				case string:
					if bytes.Contains(payload, []byte(v)) {
						return true
					}
				case []byte:
					if bytes.Contains(payload, v) {
						return true
					}
				}
			}
			return false
		},

		// CountOccurrences counts how many times a pattern appears.
		"CountOccurrences": func(payload, pattern []byte) int {
			return bytes.Count(payload, pattern)
		},

		// IndexOf returns the first index of pattern in payload (-1 if not found).
		"IndexOf": func(payload, pattern []byte) int {
			return bytes.Index(payload, pattern)
		},

		// Entropy calculates the Shannon entropy of the payload (0-8).
		// High entropy may indicate encrypted/compressed data.
		"Entropy": func(payload []byte) float64 {
			if len(payload) == 0 {
				return 0
			}
			var freq [256]float64
			for _, b := range payload {
				freq[b]++
			}
			length := float64(len(payload))
			entropy := 0.0
			for _, f := range freq {
				if f > 0 {
					p := f / length
					entropy -= p * log2(p)
				}
			}
			return entropy
		},
	}
}

func log2(x float64) float64 {
	// log2(x) = ln(x) / ln(2)
	if x <= 0 {
		return 0
	}
	return ln(x) / ln(2)
}

func ln(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Use the standard identities for natural log approximation
	// For better precision, we use the series expansion
	if x == 1 {
		return 0
	}
	result := 0.0
	if x > 2 {
		// Reduce to range [1, 2)
		count := 0
		for x >= 2 {
			x /= 2
			count++
		}
		result = float64(count) * 0.6931471805599453 // ln(2)
	}
	// Series expansion for ln(1+y) where y = x-1
	y := x - 1.0
	term := y
	for i := 1; i <= 50; i++ {
		if i%2 == 1 {
			result += term / float64(i)
		} else {
			result -= term / float64(i)
		}
		term *= y
	}
	return result
}

var _ = strings.ToLower // suppress unused import
