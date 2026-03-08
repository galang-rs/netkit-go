package js

import (
	"fmt"
	"sync"
	"time"

	"github.com/bacot120211/netkit-go/pkg/security"
)

// PermissionScope defines what a JS script is allowed to access.
type PermissionScope struct {
	NetDial   bool
	FSRead    bool
	FSWrite   bool
	Fetch     bool
	TLSMITM   bool
	DNSLookup bool
	ProxyDial bool
	ExecSpawn bool
}

// DefaultPermissions returns a fully permissive scope.
func DefaultPermissions() *PermissionScope {
	return &PermissionScope{
		NetDial:   true,
		FSRead:    true,
		FSWrite:   true,
		Fetch:     true,
		TLSMITM:   true,
		DNSLookup: true,
		ProxyDial: true,
		ExecSpawn: true,
	}
}

// RestrictedPermissions returns a minimal permission scope.
func RestrictedPermissions() *PermissionScope {
	return &PermissionScope{}
}

// SecurityConfig configures runtime security limits.
type SecurityConfig struct {
	MaxMemoryMB  int64
	MaxCPUMs     int64 // max execution time per OnPacket call
	MaxLoopIters int64 // infinite loop guard
	PanicRecover bool
	Permissions  *PermissionScope
}

// DefaultSecurityConfig returns sensible defaults.
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		MaxMemoryMB:  256,
		MaxCPUMs:     5000,
		MaxLoopIters: 1000000,
		PanicRecover: true,
		Permissions:  DefaultPermissions(),
	}
}

var globalSecurityConfig = DefaultSecurityConfig()
var securityMu sync.RWMutex

// RegisterSecurityModule injects ctx.Security into the JS context.
func RegisterSecurityModule(jsCtx map[string]interface{}, fw *security.Firewall, sm *security.ScopeManager, bl *security.BruteforceLimiter) {
	jsCtx["Security"] = map[string]interface{}{
		// GetPermissions returns current permission scope.
		"GetPermissions": func() map[string]interface{} {
			securityMu.RLock()
			defer securityMu.RUnlock()
			p := globalSecurityConfig.Permissions
			return map[string]interface{}{
				"netDial":   p.NetDial,
				"fsRead":    p.FSRead,
				"fsWrite":   p.FSWrite,
				"fetch":     p.Fetch,
				"tlsMitm":   p.TLSMITM,
				"dnsLookup": p.DNSLookup,
				"proxyDial": p.ProxyDial,
				"execSpawn": p.ExecSpawn,
			}
		},

		// CheckPermission checks if a specific permission is granted.
		"CheckPermission": func(perm string) bool {
			securityMu.RLock()
			defer securityMu.RUnlock()
			p := globalSecurityConfig.Permissions
			switch perm {
			case "net.dial":
				return p.NetDial
			case "fs.read":
				return p.FSRead
			case "fs.write":
				return p.FSWrite
			case "fetch":
				return p.Fetch
			case "tls.mitm":
				return p.TLSMITM
			case "dns.lookup":
				return p.DNSLookup
			case "proxy.dial":
				return p.ProxyDial
			case "exec.spawn":
				return p.ExecSpawn
			default:
				return false
			}
		},

		// SetPermission sets a specific permission.
		"SetPermission": func(perm string, allowed bool) {
			securityMu.Lock()
			defer securityMu.Unlock()
			p := globalSecurityConfig.Permissions
			switch perm {
			case "net.dial":
				p.NetDial = allowed
			case "fs.read":
				p.FSRead = allowed
			case "fs.write":
				p.FSWrite = allowed
			case "fetch":
				p.Fetch = allowed
			case "tls.mitm":
				p.TLSMITM = allowed
			case "dns.lookup":
				p.DNSLookup = allowed
			case "proxy.dial":
				p.ProxyDial = allowed
			case "exec.spawn":
				p.ExecSpawn = allowed
			}
		},

		// GetLimits returns current resource limits.
		"GetLimits": func() map[string]interface{} {
			securityMu.RLock()
			defer securityMu.RUnlock()
			return map[string]interface{}{
				"maxMemoryMB":  globalSecurityConfig.MaxMemoryMB,
				"maxCPUMs":     globalSecurityConfig.MaxCPUMs,
				"maxLoopIters": globalSecurityConfig.MaxLoopIters,
				"panicRecover": globalSecurityConfig.PanicRecover,
			}
		},

		// SetMaxMemory sets the memory limit in MB.
		"SetMaxMemory": func(mb int64) {
			securityMu.Lock()
			globalSecurityConfig.MaxMemoryMB = mb
			securityMu.Unlock()
		},

		// SetMaxCPU sets the max execution time per call in ms.
		"SetMaxCPU": func(ms int64) {
			securityMu.Lock()
			globalSecurityConfig.MaxCPUMs = ms
			securityMu.Unlock()
		},

		// SetMaxLoopIters sets the infinite loop guard threshold.
		"SetMaxLoopIters": func(n int64) {
			securityMu.Lock()
			globalSecurityConfig.MaxLoopIters = n
			securityMu.Unlock()
		},

		// Firewall API
		"Firewall": map[string]interface{}{
			"AddRule": func(rule map[string]interface{}) string {
				if fw == nil {
					return "error: firewall not initialized"
				}
				r := security.FirewallRule{
					Name:     fmt.Sprint(rule["name"]),
					Priority: int(toInt64(rule["priority"])),
					Enabled:  true,
				}

				// Action
				action := fmt.Sprint(rule["action"])
				switch action {
				case "DENY":
					r.Action = security.FirewallDeny
				case "LOG":
					r.Action = security.FirewallLog
				default:
					r.Action = security.FirewallAllow
				}

				// Direction
				dir := fmt.Sprint(rule["direction"])
				switch dir {
				case "IN":
					r.Direction = security.DirectionInbound
				case "OUT":
					r.Direction = security.DirectionOutbound
				default:
					r.Direction = security.DirectionBoth
				}

				if v, ok := rule["srcIP"]; ok {
					r.SrcIP = fmt.Sprint(v)
				}
				if v, ok := rule["dstIP"]; ok {
					r.DstIP = fmt.Sprint(v)
				}
				if v, ok := rule["srcPort"]; ok {
					r.SrcPort = int(toInt64(v))
				}
				if v, ok := rule["dstPort"]; ok {
					r.DstPort = int(toInt64(v))
				}
				if v, ok := rule["protocol"]; ok {
					r.Protocol = fmt.Sprint(v)
				}

				fw.AddRule(r)
				return "ok"
			},
			"RemoveRule": func(name string) {
				if fw != nil {
					fw.RemoveRule(name)
				}
			},
			"ListRules": func() []map[string]interface{} {
				if fw == nil {
					return nil
				}
				rules := fw.ListRules()
				res := make([]map[string]interface{}, len(rules))
				for i, r := range rules {
					res[i] = map[string]interface{}{
						"name":      r.Name,
						"priority":  r.Priority,
						"action":    r.Action.String(),
						"direction": fmt.Sprintf("%d", r.Direction),
						"srcIP":     r.SrcIP,
						"dstIP":     r.DstIP,
						"srcPort":   r.SrcPort,
						"dstPort":   r.DstPort,
						"protocol":  r.Protocol,
						"enabled":   r.Enabled,
					}
				}
				return res
			},
		},

		// Scope API
		"Scope": map[string]interface{}{
			"GetRole": func() string {
				if sm == nil {
					return "Unknown"
				}
				return sm.GetRole().String()
			},
			"SetRole": func(role string) {
				if sm == nil {
					return
				}
				switch role {
				case "Client":
					sm.SetRole(security.RoleClient)
				case "Server":
					sm.SetRole(security.RoleServer)
				case "Both":
					sm.SetRole(security.RoleBoth)
				}
			},
			"GetActiveScope": func() int {
				if sm == nil {
					return int(security.ScopeAll)
				}
				return int(sm.GetActiveScope())
			},
			"SetScope": func(scope int, ttlMinutes int, reason string) {
				if sm == nil {
					return
				}
				s := security.NetworkScope(scope)
				if ttlMinutes > 0 {
					sm.SetTemporaryScope(s, time.Duration(ttlMinutes)*time.Minute, reason)
				} else {
					sm.SetAbsoluteScope(s)
				}
			},
		},

		// Bruteforce API
		"Bruteforce": map[string]interface{}{
			"GetBannedIPs": func() []string {
				if bl == nil {
					return nil
				}
				return bl.GetBannedIPs()
			},
			"UnbanIP": func(ip string) {
				if bl != nil {
					bl.UnbanIP(ip)
				}
			},
		},
	}
}

func toInt64(v interface{}) int64 {
	switch i := v.(type) {
	case int64:
		return i
	case float64:
		return int64(i)
	case int:
		return int64(i)
	default:
		return 0
	}
}
