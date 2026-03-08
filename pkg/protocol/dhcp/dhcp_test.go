package dhcp

import (
	"net"
	"testing"
)

func TestDHCP_Parse(t *testing.T) {
	// Mock DHCP Discover packet (simplified)
	data := make([]byte, 240)
	data[0] = 1 // Op (Request)
	data[1] = 1 // HType (Ethernet)
	data[2] = 6 // HLen
	data[4] = 0x12
	data[5] = 0x34
	data[6] = 0x56
	data[7] = 0x78 // Xid

	// IP addresses
	copy(data[12:16], net.IPv4(192, 168, 1, 100).To4()) // CiAddr
	copy(data[16:20], net.IPv4(0, 0, 0, 0).To4())       // YiAddr
	copy(data[20:24], net.IPv4(192, 168, 1, 1).To4())   // SiAddr
	copy(data[24:28], net.IPv4(0, 0, 0, 0).To4())       // GiAddr

	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if p.Op != 1 {
		t.Errorf("Expected Op 1, got %d", p.Op)
	}
	if p.Xid != 0x12345678 {
		t.Errorf("Expected Xid 0x12345678, got 0x%X", p.Xid)
	}
	if !p.CiAddr.Equal(net.IPv4(192, 168, 1, 100)) {
		t.Errorf("Expected CiAddr 192.168.1.100, got %v", p.CiAddr)
	}
	if !p.SiAddr.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("Expected SiAddr 192.168.1.1, got %v", p.SiAddr)
	}
}

func TestDHCP_ParseTooShort(t *testing.T) {
	data := make([]byte, 100)
	_, err := Parse(data)
	if err == nil {
		t.Error("Expected error for short packet, got nil")
	}
}
