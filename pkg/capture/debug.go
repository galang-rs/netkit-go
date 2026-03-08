package capture

import (
	"strings"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
)

// Debugger provides advanced packet inspection and "see package" functionality
type Debugger struct {
	Verbose bool
}

func NewDebugger(verbose bool) *Debugger {
	return &Debugger{Verbose: verbose}
}

// SeePacket prints a detailed view of a packet for debugging
func (d *Debugger) SeePacket(p *engine.Packet) {
	logger.Infof("%s\n", strings.Repeat("=", 60))
	logger.Infof("📦 PACKET [%s] | ID: %d | Time: %d\n", p.Protocol, p.ID, p.Timestamp)
	logger.Infof("⛓️  FLOW: %s:%d ➡️ %s:%d\n", p.Source, p.SourcePort, p.Dest, p.DestPort)

	if len(p.Metadata) > 0 {
		logger.Infof("📝 METADATA: %v\n", p.Metadata)
	}

	logger.Infof("📄 PAYLOAD:\n")
	logger.Infof("%s\n", engine.Hexdump(p.Payload))

	// Tentative parser detection
	if d.Verbose {
		d.guessProtocol(p.Payload)
	}
	logger.Infof("%s\n", strings.Repeat("=", 60))
}

func (d *Debugger) guessProtocol(data []byte) {
	if len(data) == 0 {
		return
	}

	// Simple heuristic signatures
	switch {
	case len(data) >= 4 && string(data[:4]) == "HTTP":
		logger.Successf("🔍 DETECTED: HTTP Response\n")
	case len(data) >= 3 && (data[0] == 0x16 && data[1] == 0x03):
		logger.Successf("🔍 DETECTED: TLS Handshake\n")
	case len(data) >= 24 && data[0] == 0x01 && data[21] == 0x00:
		logger.Successf("🔍 DETECTED: KCP Protocol\n")
	case len(data) >= 1 && (data[0] >= 0x80 && data[0] <= 0x83):
		logger.Successf("🔍 DETECTED: QUIC (heuristic)\n")
	default:
		// Could add more for RakNet, ENet, etc.
	}
}

// PacketInspector is an engine.Interceptor that logs every packet
type PacketInspector struct {
	dbg *Debugger
}

func NewPacketInspector(verbose bool) *PacketInspector {
	return &PacketInspector{dbg: NewDebugger(verbose)}
}

func (i *PacketInspector) Name() string { return "PacketInspector" }

func (i *PacketInspector) OnConnect(info *engine.ConnInfo) *engine.TunnelConfig {
	if i.dbg.Verbose {
		logger.Infof("🔌 ON CONNECT: [%s] %s -> %s (Through: %s)\n", info.Type, info.Source, info.Dest, info.Through)
	}
	return nil
}

func (i *PacketInspector) OnPacket(ctx *engine.PacketContext) error {
	i.dbg.SeePacket(ctx.Packet)
	return nil
}
