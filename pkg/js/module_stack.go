package js

import (
	"encoding/hex"
	"net"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/protocol/stack"

	"github.com/dop251/goja"
)

// StackTools provides utility functions for JS to craft raw packets.
type StackTools struct {
	vm *goja.Runtime
}

func (s *StackTools) NewIPv4(src, dst string, proto int) *stack.IPv4Header {
	return &stack.IPv4Header{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: proto,
		Src:      net.ParseIP(src),
		Dst:      net.ParseIP(dst),
	}
}

func (s *StackTools) NewTCP(srcPort, dstPort int) *stack.TCPHeader {
	return &stack.TCPHeader{
		SrcPort: srcPort,
		DstPort: dstPort,
		Window:  65535,
	}
}

func (s *StackTools) Hexdump(data []byte) string {
	return engine.Hexdump(data)
}

// RegisterStackModule injects ctx.Stack into the JS context.
func RegisterStackModule(r *Runtime, jsCtx map[string]interface{}) {
	vm := r.vm
	tools := &StackTools{vm: vm}

	jsCtx["Stack"] = map[string]interface{}{
		"NewIPv4": func(src, dst string, proto int) *stack.IPv4Header {
			return tools.NewIPv4(src, dst, proto)
		},
		"NewTCP": func(srcPort, dstPort int) *stack.TCPHeader {
			return tools.NewTCP(srcPort, dstPort)
		},
		"Hexdump": func(data []byte) string {
			return tools.Hexdump(data)
		},
		// HexEncode encodes bytes to hex string.
		"HexEncode": func(data []byte) string {
			return hex.EncodeToString(data)
		},
		// HexDecode decodes hex string to bytes.
		"HexDecode": func(s string) ([]byte, error) {
			return hex.DecodeString(s)
		},
		// ReadTTL reads the TTL from an IPv4 header (byte 8).
		"ReadTTL": func(data []byte) int {
			if len(data) < 9 {
				return -1
			}
			return int(data[8])
		},
		// ReadProtocol reads the IP protocol number (byte 9).
		"ReadIPProtocol": func(data []byte) int {
			if len(data) < 10 {
				return -1
			}
			return int(data[9])
		},
		// ReadWindowSize reads TCP window size (bytes 14-15 of TCP header).
		"ReadWindowSize": func(tcpData []byte) int {
			if len(tcpData) < 16 {
				return -1
			}
			return int(tcpData[14])<<8 | int(tcpData[15])
		},
		// ReadTCPFlags reads TCP flags byte (byte 13 of TCP header).
		"ReadTCPFlags": func(tcpData []byte) map[string]interface{} {
			if len(tcpData) < 14 {
				return nil
			}
			flags := tcpData[13]
			return map[string]interface{}{
				"FIN": flags&0x01 != 0,
				"SYN": flags&0x02 != 0,
				"RST": flags&0x04 != 0,
				"PSH": flags&0x08 != 0,
				"ACK": flags&0x10 != 0,
				"URG": flags&0x20 != 0,
				"ECE": flags&0x40 != 0,
				"CWR": flags&0x80 != 0,
				"raw": flags,
			}
		},
		// SetTTL modifies TTL in an IPv4 header.
		"SetTTL": func(data []byte, ttl int) []byte {
			if len(data) < 9 {
				return data
			}
			result := make([]byte, len(data))
			copy(result, data)
			result[8] = byte(ttl)
			return result
		},
		// SetTCPFlags sets TCP flags byte.
		"SetTCPFlags": func(tcpData []byte, flags int) []byte {
			if len(tcpData) < 14 {
				return tcpData
			}
			result := make([]byte, len(tcpData))
			copy(result, tcpData)
			result[13] = byte(flags)
			return result
		},
		// ReadSrcIP reads source IP from IPv4 header.
		"ReadSrcIP": func(data []byte) string {
			if len(data) < 16 {
				return ""
			}
			return net.IPv4(data[12], data[13], data[14], data[15]).String()
		},
		// ReadDstIP reads destination IP from IPv4 header.
		"ReadDstIP": func(data []byte) string {
			if len(data) < 20 {
				return ""
			}
			return net.IPv4(data[16], data[17], data[18], data[19]).String()
		},
		// ReadSrcPort reads source port from TCP/UDP header.
		"ReadSrcPort": func(transportData []byte) int {
			if len(transportData) < 2 {
				return -1
			}
			return int(transportData[0])<<8 | int(transportData[1])
		},
		// ReadDstPort reads destination port from TCP/UDP header.
		"ReadDstPort": func(transportData []byte) int {
			if len(transportData) < 4 {
				return -1
			}
			return int(transportData[2])<<8 | int(transportData[3])
		},
		// IsECN checks if ECN bits are set in the IP header.
		"IsECN": func(data []byte) bool {
			if len(data) < 2 {
				return false
			}
			return (data[1] & 0x03) != 0
		},
		// IsFragmented checks the fragment flags in IPv4 header.
		"IsFragmented": func(data []byte) bool {
			if len(data) < 8 {
				return false
			}
			flags := data[6] >> 5
			fragOffset := (int(data[6]&0x1F) << 8) | int(data[7])
			// More Fragments bit or non-zero fragment offset
			return (flags&0x01 != 0) || fragOffset != 0
		},
	}
}
