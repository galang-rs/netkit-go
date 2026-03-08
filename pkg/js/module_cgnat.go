package js

import (
	"context"
	"fmt"
	"time"

	"github.com/bacot120211/netkit-go/pkg/cgnat"
)

// RegisterCGNATModule injects ctx.CGNAT into the JS context.
// Provides NAT detection, bypass orchestration, and MikroTik control from scripts.
func RegisterCGNATModule(r *Runtime, jsCtx map[string]interface{}) {
	bypass := cgnat.NewBypass()

	jsCtx["CGNAT"] = map[string]interface{}{
		// Detect performs auto-detection of NAT type, ISP, network, and router.
		// Returns { natType, networkType, publicIP, localIP, isp, routerType, strategy, latencyMs }
		"Detect": func() map[string]interface{} {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result := bypass.AutoDetect(ctx)
			return map[string]interface{}{
				"natType":      result.NATType.String(),
				"canHolePunch": result.NATType.CanHolePunch(),
				"networkType":  result.NetworkType.String(),
				"publicIPv4":   result.PublicIPv4,
				"publicIPv6":   result.PublicIPv6,
				"publicPort":   result.PublicPort,
				"localIPv4":    result.LocalIPv4,
				"localIPv6":    result.LocalIPv6,
				"isp":          result.ISP.String(),
				"routerType":   result.RouterType,
				"strategy":     result.Strategy.String(),
				"latencyMs":    result.Latency.Milliseconds(),
				"upnpMapped":   result.UPnPMapped,
			}
		},

		// Execute runs the bypass with the detected strategy.
		// Returns { success, strategy, natType, routerType, publicIP, publicPort, error }
		"Execute": func(port int) map[string]interface{} {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			result, err := bypass.Execute(ctx, port)
			resp := map[string]interface{}{
				"success": err == nil,
			}
			if err != nil {
				resp["error"] = err.Error()
			}
			if result != nil {
				resp["strategy"] = result.Strategy.String()
				resp["natType"] = result.NATType.String()
				resp["routerType"] = result.RouterType
				resp["publicIPv4"] = result.PublicIPv4
				resp["publicIPv6"] = result.PublicIPv6
				resp["publicPort"] = result.PublicPort
			}
			return resp
		},

		// SetRelay configures the relay server for symmetric NAT fallback.
		"SetRelay": func(addr, token string) {
			bypass.SetRelay(addr, token, nil)
		},

		// SetTunnel configures the NK-Tunnel server for CGNAT bypass.
		// After calling this, Execute() will connect to the tunnel and return publicIP:port.
		"SetTunnel": func(server, user, pass string) {
			bypass.SetTunnel(server, user, pass)
		},

		// GetPublicEndpoint returns the current public endpoint after Execute().
		// Returns { ip, port, endpoint } or null if not available.
		"GetPublicEndpoint": func() map[string]interface{} {
			ip, port := bypass.GetPublicEndpoint()
			if ip == "" {
				return nil
			}
			return map[string]interface{}{
				"ip":       ip,
				"port":     port,
				"endpoint": fmt.Sprintf("%s:%d", ip, port),
			}
		},

		// Interfaces returns all active network interfaces.
		"Interfaces": func() []map[string]interface{} {
			ifaces := cgnat.ListInterfaces()
			result := make([]map[string]interface{}, len(ifaces))
			for i, iface := range ifaces {
				result[i] = map[string]interface{}{
					"name":   iface.Name,
					"ipv4":   iface.IPv4,
					"ipv6":   iface.IPv6,
					"type":   iface.Type.String(),
					"mtu":    iface.MTU,
					"docker": cgnat.IsDockerInterface(iface.Name),
				}
			}
			return result
		},

		// MikroTik returns a MikroTik bypass helper.
		"MikroTik": func(host, user, pass string) map[string]interface{} {
			mk := cgnat.NewMikroTikBypass(host, user, pass)
			return map[string]interface{}{
				"AddPortForward": func(extPort, intPort int, intIP, proto string) error {
					return mk.AddPortForward(extPort, intPort, intIP, proto)
				},
				"RemovePortForward": func() error {
					return mk.RemovePortForward()
				},
				"EnableUPnP": func() error {
					return mk.EnableUPnP()
				},
			}
		},
	}
}
