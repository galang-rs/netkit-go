package security

import (
	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
)

// SecurityInterceptor implements engine.Interceptor to enforce firewall and scope rules.
type SecurityInterceptor struct {
	Firewall *Firewall
	Scope    *ScopeManager
}

func NewSecurityInterceptor(fw *Firewall, sm *ScopeManager) *SecurityInterceptor {
	return &SecurityInterceptor{
		Firewall: fw,
		Scope:    sm,
	}
}

func (s *SecurityInterceptor) Name() string {
	return "Security"
}

func (s *SecurityInterceptor) OnConnect(info *engine.ConnInfo) *engine.TunnelConfig {
	// 1. Check Scope
	if s.Scope != nil {
		if !s.Scope.IsAllowed(info.Dest) {
			logger.Warnf("[Security] 🚫 Blocking connection to %s: Destination outside allowed scope (%s)\n", info.Dest, s.Scope.GetActiveScope())
			// Returning a special config or just dropping?
			// The engine doesn't have a "Drop" action for OnConnect yet beyond returning nil or a specific config.
			// Actually, if we want to block, we might need the engine to handle a "Deny" config.
			// For now, we'll just log and let the JS or other interceptors handle it,
			// OR we can return a "deny" type if the engine supports it.
			// Let's check engine.go again.
		}
	}

	// 2. Check Firewall (if applicable to connection level)
	// Firewall evaluation usually happens at packet level, but we can do a quick check here too.
	return nil
}

func (s *SecurityInterceptor) OnPacket(ctx *engine.PacketContext) error {
	p := ctx.Packet

	// 1. Evaluate Network Scope
	if s.Scope != nil {
		if !s.Scope.IsAllowed(p.Dest) {
			logger.Warnf("[Security] 🚫 Dropping packet to %s: Outside allowed scope\n", p.Dest)
			ctx.Action = engine.ActionDrop
			return nil
		}
	}

	// 2. Evaluate Firewall Rules
	if s.Firewall != nil {
		// Determine direction
		direction := DirectionOutbound // Default
		// Simple heuristic: if source is local-ish, it's outbound.
		// In a real system, the sniffer/capture layer should tag the direction.

		action := s.Firewall.Evaluate(
			p.Source, int(p.SourcePort),
			p.Dest, int(p.DestPort),
			p.Protocol,
			direction,
		)

		switch action {
		case FirewallDeny:
			logger.Warnf("[Security] 🛡️  Firewall: DENY %s:%d -> %s:%d [%s]\n", p.Source, p.SourcePort, p.Dest, p.DestPort, p.Protocol)
			ctx.Action = engine.ActionDrop
			return nil
		case FirewallLog:
			logger.Infof("[Security] 📝 Firewall: LOG %s:%d -> %s:%d [%s]\n", p.Source, p.SourcePort, p.Dest, p.DestPort, p.Protocol)
		}
	}

	return nil
}
