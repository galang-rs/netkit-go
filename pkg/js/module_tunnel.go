package js

import (
	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/protocol/tls"
	"github.com/bacot120211/netkit-go/pkg/tunnel"
	"github.com/dop251/goja"
)

// RegisterTunnelModule injects Tunnel into the JS context.
func RegisterTunnelModule(r *Runtime, jsCtx map[string]interface{}, eng engine.Engine, ca *tls.CA) {
	vm := r.vm
	jsCtx["Tunnel"] = map[string]interface{}{
		// CreateServer starts an NK-Tunnel server.
		"CreateServer": func(options map[string]interface{}) (goja.Value, error) {
			addr, _ := options["addr"].(string)
			portRange, _ := options["portRange"].(string)
			user, _ := options["user"].(string)
			pass, _ := options["pass"].(string)

			logger.Printf("[JS] 🏰 Tunnel.CreateServer called on %s (Range: %s)\n", addr, portRange)

			if eng == nil || ca == nil {
				return vm.ToValue(nil), logger.Errorf("engine or CA not available")
			}

			authFunc := func(u, p string) bool {
				if user == "" && pass == "" {
					return true
				}
				return u == user && p == pass
			}

			srv := tunnel.NewNKTunnelServer(addr, authFunc, eng, ca, portRange)
			go func() {
				if err := srv.Start(); err != nil {
					logger.Printf("[JS] Tunnel Server Error: %v\n", err)
				}
			}()

			return vm.ToValue(map[string]interface{}{
				"addr": addr,
				"user": user,
			}), nil
		},

		// Connect starts an NK-Tunnel client.
		"Connect": func(options map[string]interface{}) (goja.Value, error) {
			server, _ := options["server"].(string)
			user, _ := options["user"].(string)
			pass, _ := options["pass"].(string)
			local, _ := options["local"].(string)
			remote, _ := options["remote"].(string)
			proto, _ := options["proto"].(string)

			if proto == "" {
				proto = "tcp"
			}

			logger.Printf("[JS] 🚀 Tunnel.Connect to %s (Local: %s, Proto: %s)\n", server, local, proto)

			cli := tunnel.NewNKTunnelClient(server, user, pass, local, remote, proto)

			// Parse optional SSH transport config
			if sshOpt, ok := options["ssh"]; ok {
				if sshMap, ok := sshOpt.(map[string]interface{}); ok {
					sshCfg := &tunnel.SSHTransportConfig{Port: 22}
					if v, ok := sshMap["host"].(string); ok {
						sshCfg.Host = v
					}
					if v, ok := sshMap["port"].(int64); ok {
						sshCfg.Port = int(v)
					}
					if v, ok := sshMap["user"].(string); ok {
						sshCfg.User = v
					}
					if v, ok := sshMap["pass"].(string); ok {
						sshCfg.Pass = v
					}
					if v, ok := sshMap["key"].(string); ok {
						sshCfg.PrivateKey = v
					}
					cli.SSHConfig = sshCfg
					logger.Printf("[JS] 🔑 Tunnel.Connect with SSH transport via %s:%d\n", sshCfg.Host, sshCfg.Port)
				}
			}

			go func() {
				if err := cli.Start(); err != nil {
					logger.Printf("[JS] Tunnel Client Error: %v\n", err)
				}
			}()

			return vm.ToValue(map[string]interface{}{
				"server": server,
				"local":  local,
				"proto":  proto,
				"ssh":    cli.SSHConfig != nil,
			}), nil
		},

		// SSHReverse starts an SSH reverse port forwarding tunnel (ssh -R).
		// Exposes a local service on the SSH server's public IP.
		"SSHReverse": func(options map[string]interface{}) (goja.Value, error) {
			local, _ := options["local"].(string)
			remote, _ := options["remote"].(string)

			if remote == "" {
				remote = "0.0.0.0:80"
			}

			sshCfg := parseSSHConfig(options)
			if sshCfg == nil {
				return vm.ToValue(nil), logger.Errorf("SSHReverse requires ssh config (host, user, pass/key)")
			}

			logger.Printf("[JS] 🔑 Tunnel.SSHReverse %s@%s:%d → remote %s → local %s\n",
				sshCfg.User, sshCfg.Host, sshCfg.Port, remote, local)

			rt := tunnel.NewSSHReverseTunnel(sshCfg, local, remote)
			go func() {
				if err := rt.Start(); err != nil {
					logger.Printf("[JS] SSH Reverse Tunnel Error: %v\n", err)
				}
			}()

			return vm.ToValue(map[string]interface{}{
				"host":   sshCfg.Host,
				"remote": remote,
				"local":  local,
			}), nil
		},
	}
}

// parseSSHConfig extracts SSHTransportConfig from a JS options map.
// Supports both top-level SSH fields and nested "ssh" object.
func parseSSHConfig(options map[string]interface{}) *tunnel.SSHTransportConfig {
	var sshMap map[string]interface{}

	// Check for nested "ssh" object first
	if sshOpt, ok := options["ssh"]; ok {
		if m, ok := sshOpt.(map[string]interface{}); ok {
			sshMap = m
		}
	}

	// Fall back to top-level fields (host, user, pass, key, port)
	if sshMap == nil {
		if _, hasHost := options["host"]; hasHost {
			sshMap = options
		}
	}

	if sshMap == nil {
		return nil
	}

	cfg := &tunnel.SSHTransportConfig{Port: 22}
	if v, ok := sshMap["host"].(string); ok {
		cfg.Host = v
	}
	if v, ok := sshMap["port"].(int64); ok {
		cfg.Port = int(v)
	}
	if v, ok := sshMap["user"].(string); ok {
		cfg.User = v
	}
	if v, ok := sshMap["pass"].(string); ok {
		cfg.Pass = v
	}
	if v, ok := sshMap["key"].(string); ok {
		cfg.PrivateKey = v
	}

	if cfg.Host == "" || cfg.User == "" {
		return nil
	}

	return cfg
}
