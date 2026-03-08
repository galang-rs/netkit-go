package rtp

import (
	"encoding/binary"
	"testing"
)

func TestRTP_Parse(t *testing.T) {
	data := make([]byte, 12)
	data[0] = 0x80 // V=2, P=0, X=0, CC=0
	data[1] = 0x7F // M=0, PT=127
	data[2] = 0x12
	data[3] = 0x34 // Sequence 0x1234
	data[4] = 0x56
	data[5] = 0x78
	data[6] = 0x90
	data[7] = 0xAB // Timestamp 0x567890AB
	data[8] = 0xDE
	data[9] = 0xAD
	binary.BigEndian.PutUint32(data[8:12], 0xDEADBEEF)

	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if p.Version != 2 {
		t.Errorf("Expected version 2, got %d", p.Version)
	}
	if p.PayloadType != 127 {
		t.Errorf("Expected PT 127, got %d", p.PayloadType)
	}
	if p.SSRC != 0xDEADBEEF {
		t.Errorf("Expected SSRC 0xDEADBEEF, got 0x%X", p.SSRC)
	}
}
