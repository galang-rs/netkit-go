package engine

import (
	"strconv"
	"strings"
)

// Filter determines if a packet should be processed.
// Tokens are pre-parsed and cached to avoid per-packet allocation.
type Filter struct {
	Expression string
	tokens     []string // cached lowercase tokens
}

// NewFilter creates a filter with pre-parsed tokens for maximum performance.
func NewFilter(expr string) *Filter {
	f := &Filter{Expression: expr}
	if expr != "" {
		f.tokens = strings.Split(strings.ToLower(expr), " ")
	}
	return f
}

// Matches checks if the packet matches the filter expression.
// Uses cached tokens — zero allocations per call.
func (f *Filter) Matches(p *Packet) bool {
	if f.Expression == "" || len(f.tokens) == 0 {
		return true
	}

	parts := f.tokens
	for i := 0; i < len(parts); i++ {
		switch parts[i] {
		case "proto":
			if i+1 < len(parts) && strings.ToLower(p.Protocol) != parts[i+1] {
				return false
			}
		case "src":
			if i+1 < len(parts) && !strings.Contains(strings.ToLower(p.Source), parts[i+1]) {
				return false
			}
		case "dst":
			if i+1 < len(parts) && !strings.Contains(strings.ToLower(p.Dest), parts[i+1]) {
				return false
			}
		case "port":
			if i+1 < len(parts) {
				port, err := strconv.Atoi(parts[i+1])
				if err == nil && int(p.SourcePort) != port && int(p.DestPort) != port {
					return false
				}
			}
		case "portrange":
			if i+1 < len(parts) {
				rangeParts := strings.Split(parts[i+1], "-")
				if len(rangeParts) == 2 {
					min, err1 := strconv.Atoi(rangeParts[0])
					max, err2 := strconv.Atoi(rangeParts[1])
					if err1 == nil && err2 == nil &&
						(int(p.SourcePort) < min || int(p.SourcePort) > max) &&
						(int(p.DestPort) < min || int(p.DestPort) > max) {
						return false
					}
				}
			}
		}
	}

	return true
}
