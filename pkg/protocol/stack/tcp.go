package stack

import (
	"encoding/binary"
	"net"
)

// TCPHeader represents a TCP header
type TCPHeader struct {
	SrcPort    int
	DstPort    int
	Seq        uint32
	Ack        uint32
	DataOffset int // in 32-bit words
	Flags      int
	Window     int
	Checksum   int
	Urgent     int
	Options    []byte
}

// Serialize crafts a raw TCP header
func (h *TCPHeader) Serialize(srcIP, dstIP net.IP, payload []byte) []byte {
	size := 20 + len(h.Options)
	h.DataOffset = size / 4
	b := make([]byte, size)

	binary.BigEndian.PutUint16(b[0:2], uint16(h.SrcPort))
	binary.BigEndian.PutUint16(b[2:4], uint16(h.DstPort))
	binary.BigEndian.PutUint32(b[4:8], h.Seq)
	binary.BigEndian.PutUint32(b[8:12], h.Ack)
	b[12] = byte(h.DataOffset << 4)
	b[13] = byte(h.Flags)
	binary.BigEndian.PutUint16(b[14:16], uint16(h.Window))
	binary.BigEndian.PutUint16(b[16:18], 0) // Initialize to 0 for checksum calculation
	binary.BigEndian.PutUint16(b[18:20], uint16(h.Urgent))
	if len(h.Options) > 0 {
		copy(b[20:], h.Options)
	}

	// Pseudo-header for checksum
	ph := make([]byte, 12)
	copy(ph[0:4], srcIP.To4())
	copy(ph[4:8], dstIP.To4())
	ph[8] = 0
	ph[9] = 6 // Protocol TCP
	binary.BigEndian.PutUint16(ph[10:12], uint16(size+len(payload)))

	// Calculate checksum
	full := append(ph, b...)
	full = append(full, payload...)
	h.Checksum = int(CalculateChecksum(full))
	binary.BigEndian.PutUint16(b[16:18], uint16(h.Checksum))

	return b
}
