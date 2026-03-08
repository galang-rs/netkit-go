package l2tp

import (
	"encoding/binary"
	"fmt"
)

// L2TP Packet Structure (RFC 2661)
type L2TPPacket struct {
	Flags     uint16
	TunnelID  uint16
	SessionID uint16
	Ns        uint16
	Nr        uint16
}

func Parse(data []byte) (*L2TPPacket, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("l2tp packet too short")
	}

	p := &L2TPPacket{
		Flags: binary.BigEndian.Uint16(data[0:2]),
	}

	// Simplified parsing for Control Messages (T bit set)
	if p.Flags&0x8000 != 0 {
		if len(data) < 12 {
			return nil, fmt.Errorf("l2tp control packet too short")
		}
		p.TunnelID = binary.BigEndian.Uint16(data[4:6])
		p.SessionID = binary.BigEndian.Uint16(data[6:8])
		p.Ns = binary.BigEndian.Uint16(data[8:10])
		p.Nr = binary.BigEndian.Uint16(data[10:12])
	} else {
		p.TunnelID = binary.BigEndian.Uint16(data[2:4])
		p.SessionID = binary.BigEndian.Uint16(data[4:6])
	}

	return p, nil
}
