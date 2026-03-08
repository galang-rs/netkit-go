package interceptor

import (
	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/protocol/tls"
)

type JA3Interceptor struct{}

func (j *JA3Interceptor) Name() string {
	return "JA3 Fingerprinter"
}

func (j *JA3Interceptor) OnConnect(conn *engine.ConnInfo) *engine.TunnelConfig {
	return nil
}

func (j *JA3Interceptor) OnPacket(ctx *engine.PacketContext) error {
	// Only process TCP/TLS packets for JA3
	if ctx.Packet.Protocol == "TLS" || ctx.Packet.Protocol == "TCP" {
		ja3String, ja3Hash := tls.CalculateJA3(ctx.Packet.Payload)
		if ja3Hash != "" {
			if ctx.Packet.Metadata == nil {
				ctx.Packet.Metadata = make(map[string]interface{})
			}
			ctx.Packet.Metadata["JA3Hash"] = ja3Hash
			ctx.Packet.Metadata["JA3String"] = ja3String
		}
	}
	return nil
}
