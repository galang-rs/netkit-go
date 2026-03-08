package tftp

import (
	"testing"
)

func TestTFTP_Parse(t *testing.T) {
	// RRQ (Read Request) for "test.txt" octet
	data := []byte{0x00, 0x01, 't', 'e', 's', 't', '.', 't', 'x', 't', 0x00, 'o', 'c', 't', 'e', 't', 0x00}

	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if p.OpCode != OpRead {
		t.Errorf("Expected opcode 1, got %d", p.OpCode)
	}
	if p.Value != "test.txt" {
		t.Errorf("Expected value 'test.txt', got %q", p.Value)
	}
}

func TestTFTP_ParseError(t *testing.T) {
	// Error packet
	data := []byte{0x00, 0x05, 0x00, 0x01, 'F', 'i', 'l', 'e', ' ', 'n', 'o', 't', ' ', 'f', 'o', 'u', 'n', 'd', 0x00}

	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if p.OpCode != OpError {
		t.Errorf("Expected opcode 5, got %d", p.OpCode)
	}
	if p.Value != "File not found" {
		t.Errorf("Expected value 'File not found', got %q", p.Value)
	}
}
