package protocol

import (
	"testing"
)

func TestDetectProtocol(t *testing.T) {
	tests := []struct {
		name     string
		port     uint16
		data     []byte
		expected string
	}{
		{"DNS Port", 53, nil, "DNS"},
		{"DHCP Port 67", 67, nil, "DHCP"},
		{"NTP Port", 123, nil, "NTP"},
		{"STUN Port", 3478, nil, "STUN"},
		{"STUN Payload", 12345, []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "STUN"},
		{"Unknown UDP", 9999, []byte{0x00, 0x01}, "UDP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectProtocol(tt.port, tt.data)
			if got != tt.expected {
				t.Errorf("DetectProtocol() = %v, want %v", got, tt.expected)
			}
		})
	}
}
