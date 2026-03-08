package stack

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IPv6Header represents an IPv6 header.
type IPv6Header struct {
	Version      int
	TrafficClass int
	FlowLabel    int
	PayloadLen   int
	NextHeader   int // 6 = TCP, 17 = UDP, 58 = ICMPv6
	HopLimit     int
	Src          net.IP
	Dst          net.IP
}

// Serialize crafts a raw IPv6 header (40 bytes).
func (h *IPv6Header) Serialize() []byte {
	b := make([]byte, 40)

	// Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits)
	vtcfl := uint32(h.Version)<<28 |
		uint32(h.TrafficClass)<<20 |
		uint32(h.FlowLabel&0xFFFFF)
	binary.BigEndian.PutUint32(b[0:4], vtcfl)

	// Payload Length
	binary.BigEndian.PutUint16(b[4:6], uint16(h.PayloadLen))

	// Next Header
	b[6] = byte(h.NextHeader)

	// Hop Limit
	b[7] = byte(h.HopLimit)

	// Source address (16 bytes)
	src16 := h.Src.To16()
	if src16 != nil {
		copy(b[8:24], src16)
	}

	// Destination address (16 bytes)
	dst16 := h.Dst.To16()
	if dst16 != nil {
		copy(b[24:40], dst16)
	}

	return b
}

// ParseIPv6Header parses raw bytes into an IPv6 header.
func ParseIPv6Header(data []byte) (*IPv6Header, error) {
	if len(data) < 40 {
		return nil, ErrTooShort
	}

	vtcfl := binary.BigEndian.Uint32(data[0:4])

	return &IPv6Header{
		Version:      int((vtcfl >> 28) & 0xF),
		TrafficClass: int((vtcfl >> 20) & 0xFF),
		FlowLabel:    int(vtcfl & 0xFFFFF),
		PayloadLen:   int(binary.BigEndian.Uint16(data[4:6])),
		NextHeader:   int(data[6]),
		HopLimit:     int(data[7]),
		Src:          net.IP(data[8:24]),
		Dst:          net.IP(data[24:40]),
	}, nil
}

// TCPSerializeV6 creates TCP header with IPv6 pseudo-header checksum.
func (h *TCPHeader) SerializeV6(srcIP, dstIP net.IP, payload []byte) []byte {
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
	binary.BigEndian.PutUint16(b[16:18], 0)
	binary.BigEndian.PutUint16(b[18:20], uint16(h.Urgent))
	if len(h.Options) > 0 {
		copy(b[20:], h.Options)
	}

	// IPv6 pseudo-header for checksum
	ph := make([]byte, 40)
	copy(ph[0:16], srcIP.To16())
	copy(ph[16:32], dstIP.To16())
	binary.BigEndian.PutUint32(ph[32:36], uint32(size+len(payload)))
	ph[39] = 6 // TCP protocol

	full := append(ph, b...)
	full = append(full, payload...)
	h.Checksum = int(CalculateChecksum(full))
	binary.BigEndian.PutUint16(b[16:18], uint16(h.Checksum))

	return b
}

// UDPSerializeV6 creates UDP header with IPv6 pseudo-header checksum.
func (h *UDPHeader) SerializeV6(srcIP, dstIP net.IP, payload []byte) []byte {
	size := 8
	h.Length = size + len(payload)
	b := make([]byte, size)

	binary.BigEndian.PutUint16(b[0:2], uint16(h.SrcPort))
	binary.BigEndian.PutUint16(b[2:4], uint16(h.DstPort))
	binary.BigEndian.PutUint16(b[4:6], uint16(h.Length))
	binary.BigEndian.PutUint16(b[6:8], 0)

	// IPv6 pseudo-header
	ph := make([]byte, 40)
	copy(ph[0:16], srcIP.To16())
	copy(ph[16:32], dstIP.To16())
	binary.BigEndian.PutUint32(ph[32:36], uint32(h.Length))
	ph[39] = 17 // UDP protocol

	full := append(ph, b...)
	full = append(full, payload...)
	h.Checksum = int(CalculateChecksum(full))
	binary.BigEndian.PutUint16(b[6:8], uint16(h.Checksum))

	return b
}

// IsIPv6 detects if raw packet starts with IPv6 header.
func IsIPv6(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	return (data[0] >> 4) == 6
}

// IsIPv4 detects if raw packet starts with IPv4 header.
func IsIPv4(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	return (data[0] >> 4) == 4
}

// Errors
var ErrTooShort = fmt.Errorf("packet too short")
