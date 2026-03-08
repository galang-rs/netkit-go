package snmp

import (
	"testing"
)

func TestSNMP_Parse(t *testing.T) {
	// Minimal valid looking ASN.1 Sequence
	data := []byte{0x30, 0x08, 0x02, 0x01, 0x01, 0x04, 0x03, 0x70, 0x75, 0x62}

	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if p == nil {
		t.Fatal("Expected packet, got nil")
	}
}

func TestSNMP_InvalidHeader(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02}
	_, err := Parse(data)
	if err == nil {
		t.Error("Expected error for invalid header")
	}
}
