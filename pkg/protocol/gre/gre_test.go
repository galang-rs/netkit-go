package gre

import (
	"testing"
)

func TestGRE_Parse(t *testing.T) {
	data := []byte{0x00, 0x00, 0x08, 0x00} // Protocol IP (0x0800)

	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if p.Protocol != 0x0800 {
		t.Errorf("Expected protocol 0x0800, got 0x%04X", p.Protocol)
	}
}
