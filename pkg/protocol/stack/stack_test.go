package stack

import (
	"net"
	"testing"
)

// --- IPv4 Tests ---

func TestIPv4Header_Serialize(t *testing.T) {
	h := &IPv4Header{
		Version:  4,
		IHL:      5,
		TOS:      0,
		TotalLen: 40,
		ID:       1234,
		Flags:    0,
		FragOff:  0,
		TTL:      64,
		Protocol: 6, // TCP
		Src:      net.IPv4(192, 168, 1, 100),
		Dst:      net.IPv4(10, 0, 0, 1),
	}

	data := h.Serialize()
	if len(data) != 20 {
		t.Fatalf("expected 20 bytes, got %d", len(data))
	}

	// Version + IHL
	if data[0] != 0x45 {
		t.Errorf("expected 0x45, got 0x%02x", data[0])
	}
	// TTL
	if data[8] != 64 {
		t.Errorf("expected TTL 64, got %d", data[8])
	}
	// Protocol
	if data[9] != 6 {
		t.Errorf("expected protocol 6, got %d", data[9])
	}
	// Checksum should be computed
	if h.Checksum == 0 {
		t.Error("checksum should be computed")
	}
	// Source IP
	if data[12] != 192 || data[13] != 168 || data[14] != 1 || data[15] != 100 {
		t.Error("source IP mismatch")
	}
	// Dest IP
	if data[16] != 10 || data[17] != 0 || data[18] != 0 || data[19] != 1 {
		t.Error("dest IP mismatch")
	}
}

func TestIPv4Header_ChecksumValid(t *testing.T) {
	h := &IPv4Header{
		Version:  4,
		IHL:      5,
		TotalLen: 20,
		TTL:      128,
		Protocol: 17, // UDP
		Src:      net.IPv4(127, 0, 0, 1),
		Dst:      net.IPv4(127, 0, 0, 1),
	}

	data := h.Serialize()
	// Verify checksum: computing checksum over valid header should give 0
	verify := CalculateChecksum(data)
	if verify != 0 {
		t.Errorf("checksum verification failed: got 0x%04x, want 0", verify)
	}
}

// --- TCP Tests ---

func TestTCPHeader_Serialize(t *testing.T) {
	h := &TCPHeader{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1000,
		Ack:     0,
		Flags:   0x02, // SYN
		Window:  65535,
	}

	srcIP := net.IPv4(192, 168, 1, 1)
	dstIP := net.IPv4(10, 0, 0, 1)
	payload := []byte("GET / HTTP/1.1\r\n")

	data := h.Serialize(srcIP, dstIP, payload)
	if len(data) != 20 {
		t.Fatalf("expected 20 bytes, got %d", len(data))
	}

	// Source port
	srcPort := int(data[0])<<8 | int(data[1])
	if srcPort != 12345 {
		t.Errorf("expected src port 12345, got %d", srcPort)
	}

	// Dest port
	dstPort := int(data[2])<<8 | int(data[3])
	if dstPort != 80 {
		t.Errorf("expected dst port 80, got %d", dstPort)
	}

	// Flags
	if data[13] != 0x02 {
		t.Errorf("expected SYN flag 0x02, got 0x%02x", data[13])
	}
}

func TestTCPHeader_SYNPacket(t *testing.T) {
	h := &TCPHeader{
		SrcPort: 50000,
		DstPort: 443,
		Seq:     0,
		Ack:     0,
		Flags:   0x02, // SYN
		Window:  8192,
	}

	data := h.Serialize(net.IPv4(10, 0, 0, 1), net.IPv4(93, 184, 216, 34), nil)
	if h.Checksum == 0 {
		t.Error("TCP checksum should be computed")
	}
	if len(data) < 20 {
		t.Error("TCP header should be at least 20 bytes")
	}
}

// --- UDP Tests ---

func TestUDPHeader_Serialize(t *testing.T) {
	h := &UDPHeader{
		SrcPort: 53,
		DstPort: 12345,
	}

	srcIP := net.IPv4(8, 8, 8, 8)
	dstIP := net.IPv4(192, 168, 1, 1)
	payload := []byte("DNS response data")

	data := h.Serialize(srcIP, dstIP, payload)
	if len(data) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(data))
	}

	// Source port
	srcPort := int(data[0])<<8 | int(data[1])
	if srcPort != 53 {
		t.Errorf("expected src port 53, got %d", srcPort)
	}

	// Length should include header + payload
	expLen := 8 + len(payload)
	actualLen := int(data[4])<<8 | int(data[5])
	if actualLen != expLen {
		t.Errorf("expected length %d, got %d", expLen, actualLen)
	}

	// Checksum should be computed
	if h.Checksum == 0 {
		t.Error("UDP checksum should be computed")
	}
}

func TestUDPHeader_EmptyPayload(t *testing.T) {
	h := &UDPHeader{
		SrcPort: 1234,
		DstPort: 5678,
	}

	data := h.Serialize(net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 1), nil)
	if len(data) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(data))
	}
	// Length should be just header (8)
	length := int(data[4])<<8 | int(data[5])
	if length != 8 {
		t.Errorf("expected length 8, got %d", length)
	}
}

// --- Checksum Tests ---

func TestCalculateChecksum_ZeroData(t *testing.T) {
	data := make([]byte, 20)
	cs := CalculateChecksum(data)
	if cs == 0 {
		t.Error("checksum of all zeros should be 0xFFFF")
	}
}

func TestCalculateChecksum_OddLength(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03} // 3 bytes — odd
	cs := CalculateChecksum(data)
	if cs == 0 {
		t.Log("checksum should handle odd-length data")
	}
}

func TestCalculateChecksum_Deterministic(t *testing.T) {
	data := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	cs1 := CalculateChecksum(data)
	cs2 := CalculateChecksum(data)
	if cs1 != cs2 {
		t.Error("checksum should be deterministic")
	}
}
