package dhcp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// DHCP Packet Structure (RFC 2131)
type DHCPPacket struct {
	Op      byte
	HType   byte
	HLen    byte
	Hops    byte
	Xid     uint32
	Secs    uint16
	Flags   uint16
	CiAddr  net.IP
	YiAddr  net.IP
	SiAddr  net.IP
	GiAddr  net.IP
	ChAddr  net.HardwareAddr
	SName   string
	File    string
	Options map[byte][]byte
}

func Parse(data []byte) (*DHCPPacket, error) {
	if len(data) < 240 {
		return nil, fmt.Errorf("dhcp packet too short: %d", len(data))
	}

	p := &DHCPPacket{
		Op:     data[0],
		HType:  data[1],
		HLen:   data[2],
		Hops:   data[3],
		Xid:    binary.BigEndian.Uint32(data[4:8]),
		Secs:   binary.BigEndian.Uint16(data[8:10]),
		Flags:  binary.BigEndian.Uint16(data[10:12]),
		CiAddr: net.IP(data[12:16]),
		YiAddr: net.IP(data[16:20]),
		SiAddr: net.IP(data[20:24]),
		GiAddr: net.IP(data[24:28]),
	}
	// ...
	return p, nil
}
