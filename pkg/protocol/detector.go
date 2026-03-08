package protocol

import (
	"github.com/bacot120211/netkit-go/pkg/protocol/dhcp"
	"github.com/bacot120211/netkit-go/pkg/protocol/stun"
)

// DetectProtocol attempts to identify the protocol from UDP port or payload
func DetectProtocol(port uint16, data []byte) string {
	switch port {
	case 53:
		return "DNS"
	case 67, 68:
		return "DHCP"
	case 69:
		return "TFTP"
	case 123:
		return "NTP"
	case 161, 162:
		return "SNMP"
	case 3478:
		return "STUN"
	case 1701:
		return "L2TP"
	case 5004, 5005:
		return "RTP/RTCP"
	}

	// Payload-based heuristic detection
	if _, err := stun.Parse(data); err == nil {
		return "STUN"
	}
	if _, err := dhcp.Parse(data); err == nil {
		return "DHCP"
	}

	return "UDP"
}
