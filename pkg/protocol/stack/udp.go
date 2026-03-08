package stack

import (
	"encoding/binary"
	"net"
)

// UDPHeader represents a UDP header
type UDPHeader struct {
	SrcPort  int
	DstPort  int
	Length   int
	Checksum int
}

// Serialize crafts a raw UDP header
func (h *UDPHeader) Serialize(srcIP, dstIP net.IP, payload []byte) []byte {
	size := 8
	h.Length = size + len(payload)
	b := make([]byte, size)

	binary.BigEndian.PutUint16(b[0:2], uint16(h.SrcPort))
	binary.BigEndian.PutUint16(b[2:4], uint16(h.DstPort))
	binary.BigEndian.PutUint16(b[4:6], uint16(h.Length))
	binary.BigEndian.PutUint16(b[6:8], 0) // Checksum initialized to 0

	// Pseudo-header for checksum
	ph := make([]byte, 12)
	copy(ph[0:4], srcIP.To4())
	copy(ph[4:8], dstIP.To4())
	ph[8] = 0
	ph[9] = 17 // Protocol UDP
	binary.BigEndian.PutUint16(ph[10:12], uint16(h.Length))

	// Calculate checksum
	full := append(ph, b...)
	full = append(full, payload...)
	h.Checksum = int(CalculateChecksum(full))
	binary.BigEndian.PutUint16(b[6:8], uint16(h.Checksum))

	return b
}
