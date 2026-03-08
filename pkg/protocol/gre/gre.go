package gre

import (
	"encoding/binary"
	"fmt"
)

// GRE Header Structure (RFC 1701/2784)
type GREPacket struct {
	Flags    uint16
	Protocol uint16
}

func Parse(data []byte) (*GREPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("gre packet too short")
	}

	p := &GREPacket{
		Flags:    binary.BigEndian.Uint16(data[0:2]),
		Protocol: binary.BigEndian.Uint16(data[2:4]),
	}

	return p, nil
}
