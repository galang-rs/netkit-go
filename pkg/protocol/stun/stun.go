package stun

import (
	"encoding/binary"
	"fmt"
)

// STUN Packet Structure (RFC 5389)
type STUNPacket struct {
	Type          uint16
	Length        uint16
	MagicCookie   uint32
	TransactionID [12]byte
}

func Parse(data []byte) (*STUNPacket, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("stun packet too short")
	}

	p := &STUNPacket{
		Type:        binary.BigEndian.Uint16(data[0:2]),
		Length:      binary.BigEndian.Uint16(data[2:4]),
		MagicCookie: binary.BigEndian.Uint32(data[4:8]),
	}
	copy(p.TransactionID[:], data[8:20])

	// STUN magic cookie is always 0x2112A442
	if p.MagicCookie != 0x2112A442 {
		return nil, fmt.Errorf("invalid STUN magic cookie: %X", p.MagicCookie)
	}

	return p, nil
}
