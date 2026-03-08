package l2tp

import (
	"testing"
)

func TestL2TP_Parse(t *testing.T) {
	// L2TP Control Message Header
	data := make([]byte, 12)
	data[0] = 0xC8 // T=1, L=1, S=1
	data[1] = 0x02 // Ver=2
	data[4] = 0x12
	data[5] = 0x34 // Tunnel ID 0x1234
	data[6] = 0x56
	data[7] = 0x78 // Session ID 0x5678

	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if p.TunnelID != 0x1234 {
		t.Errorf("Expected tunnel ID 0x1234, got 0x%X", p.TunnelID)
	}
	if p.SessionID != 0x5678 {
		t.Errorf("Expected session ID 0x5678, got 0x%X", p.SessionID)
	}
}
