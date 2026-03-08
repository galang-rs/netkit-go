package ntp

import (
	"encoding/binary"
	"time"
)

// NTPPacket (RFC 5905)
type NTPPacket struct {
	Settings       uint8 // Mode, Version, Leap
	Stratum        uint8
	Poll           int8
	Precision      int8
	RootDelay      uint32
	RootDispersion uint32
	ReferenceID    uint32
	RefTimestamp   uint64
	OrigTimestamp  uint64
	RecvTimestamp  uint64
	TransTimestamp uint64
}

func Parse(data []byte) *NTPPacket {
	if len(data) < 48 {
		return nil
	}
	return &NTPPacket{
		Settings:       data[0],
		Stratum:        data[1],
		Poll:           int8(data[2]),
		Precision:      int8(data[3]),
		RootDelay:      binary.BigEndian.Uint32(data[4:8]),
		RootDispersion: binary.BigEndian.Uint32(data[8:12]),
		ReferenceID:    binary.BigEndian.Uint32(data[12:16]),
		RefTimestamp:   binary.BigEndian.Uint64(data[16:24]),
		OrigTimestamp:  binary.BigEndian.Uint64(data[24:32]),
		RecvTimestamp:  binary.BigEndian.Uint64(data[32:40]),
		TransTimestamp: binary.BigEndian.Uint64(data[40:48]),
	}
}

func (p *NTPPacket) Time() time.Time {
	// NTP epoch is 1900-01-01
	seconds := uint32(p.TransTimestamp >> 32)
	return time.Unix(int64(seconds)-2208988800, 0)
}
