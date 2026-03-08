package stack

import (
	"encoding/binary"
	"net"
)

// EthernetHeader represents an Ethernet II header
type EthernetHeader struct {
	DstAddr   net.HardwareAddr
	SrcAddr   net.HardwareAddr
	EtherType uint16
}

// Serialize crafts a raw Ethernet header
func (h *EthernetHeader) Serialize() []byte {
	b := make([]byte, 14)
	copy(b[0:6], h.DstAddr)
	copy(b[6:12], h.SrcAddr)
	binary.BigEndian.PutUint16(b[12:14], h.EtherType)
	return b
}
