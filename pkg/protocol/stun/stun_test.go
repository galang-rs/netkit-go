package stun

import (
	"testing"
)

func TestSTUN_Parse(t *testing.T) {
	data := make([]byte, 20)
	// STUN Binding Request
	data[0] = 0x00
	data[1] = 0x01 // Type
	data[2] = 0x00
	data[3] = 0x00 // Length 0
	data[4] = 0x21
	data[5] = 0x12
	data[6] = 0xA4
	data[7] = 0x42 // Magic Cookie

	for i := 8; i < 20; i++ {
		data[i] = byte(i) // Transaction ID
	}

	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if p.Type != 0x0001 {
		t.Errorf("Expected type 0x0001, got 0x%04X", p.Type)
	}
	if p.MagicCookie != 0x2112A442 {
		t.Errorf("Expected magic cookie 0x2112A442, got 0x%X", p.MagicCookie)
	}
}

func TestSTUN_InvalidCookie(t *testing.T) {
	data := make([]byte, 20)
	data[4] = 0x00 // Invalid cookie
	_, err := Parse(data)
	if err == nil {
		t.Error("Expected error for invalid STUN magic cookie")
	}
}
