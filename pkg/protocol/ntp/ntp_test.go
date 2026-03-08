package ntp

import (
	"testing"
)

func TestNTP_Parse(t *testing.T) {
	data := make([]byte, 48)
	data[0] = 0x1B // LI=0, VN=3, Mode=3 (Client)
	data[1] = 3    // Stratum 3

	// Transmit Timestamp (NTP Epoch: 1900-01-01)
	// 2026-03-02 13:22:03 UTC -> Approx 3981446523 seconds since 1900
	transSecs := uint32(3981446523)
	data[40] = byte(transSecs >> 24)
	data[41] = byte(transSecs >> 16)
	data[42] = byte(transSecs >> 8)
	data[43] = byte(transSecs)

	p := Parse(data)
	if p == nil {
		t.Fatal("Parse returned nil")
	}

	if p.Settings != 0x1B {
		t.Errorf("Expected settings 0x1B, got 0x%02X", p.Settings)
	}
	if p.Stratum != 3 {
		t.Errorf("Expected stratum 3, got %d", p.Stratum)
	}

	ntpTime := p.Time()
	if ntpTime.Year() != 2026 {
		t.Errorf("Expected year 2026, got %d", ntpTime.Year())
	}
}

func TestNTP_ParseNil(t *testing.T) {
	data := make([]byte, 10)
	p := Parse(data)
	if p != nil {
		t.Error("Expected nil for short packet")
	}
}
