package stack

import (
	"encoding/binary"
	"net"
)

// IPv4Header represents an IPv4 header
type IPv4Header struct {
	Version  int
	IHL      int
	TOS      int
	TotalLen int
	ID       int
	Flags    int
	FragOff  int
	TTL      int
	Protocol int
	Checksum int
	Src      net.IP
	Dst      net.IP
}

// Serialize crafts a raw IPv4 header
func (h *IPv4Header) Serialize() []byte {
	b := make([]byte, 20)
	b[0] = byte(h.Version<<4 | (h.IHL & 0x0f))
	b[1] = byte(h.TOS)
	binary.BigEndian.PutUint16(b[2:4], uint16(h.TotalLen))
	binary.BigEndian.PutUint16(b[4:6], uint16(h.ID))
	flagsFrag := (h.Flags << 13) | (h.FragOff & 0x1fff)
	binary.BigEndian.PutUint16(b[6:8], uint16(flagsFrag))
	b[8] = byte(h.TTL)
	b[9] = byte(h.Protocol)
	binary.BigEndian.PutUint16(b[10:12], uint16(h.Checksum))
	copy(b[12:16], h.Src.To4())
	copy(b[16:20], h.Dst.To4())

	// Calculate checksum if 0
	if h.Checksum == 0 {
		h.Checksum = int(CalculateChecksum(b))
		binary.BigEndian.PutUint16(b[10:12], uint16(h.Checksum))
	}

	return b
}

// CalculateChecksum computes the 16-bit one's complement sum
func CalculateChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
