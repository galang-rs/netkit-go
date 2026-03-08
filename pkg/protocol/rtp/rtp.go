package rtp

import (
	"encoding/binary"
	"fmt"
)

// RTP Packet Structure (RFC 3550)
type RTPPacket struct {
	Version     uint8
	Padding     bool
	Extension   bool
	CSRCCount   uint8
	Marker      bool
	PayloadType uint8
	Sequence    uint16
	Timestamp   uint32
	SSRC        uint32
}

func Parse(data []byte) (*RTPPacket, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("rtp packet too short")
	}

	p := &RTPPacket{
		Version:     data[0] >> 6,
		Padding:     (data[0]>>5)&0x01 == 1,
		Extension:   (data[0]>>4)&0x01 == 1,
		CSRCCount:   data[0] & 0x0F,
		Marker:      (data[1]>>7)&0x01 == 1,
		PayloadType: data[1] & 0x7F,
		Sequence:    binary.BigEndian.Uint16(data[2:4]),
		Timestamp:   binary.BigEndian.Uint32(data[4:8]),
		SSRC:        binary.BigEndian.Uint32(data[8:12]),
	}

	return p, nil
}
