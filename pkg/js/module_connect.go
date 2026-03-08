package js

import (
	"reflect"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/dop251/goja"
)

// RegisterConnectModule injects the global `connect` object into the VM.
func RegisterConnectModule(r *Runtime, jsCtx map[string]interface{}) {
	vm := r.vm
	connect := vm.NewObject()

	connect.Set("proxy", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Undefined()
		}
		arg := call.Arguments[0]
		tc := &engine.TunnelConfig{Type: "proxy"}

		if arg.ExportType().Kind() == reflect.Map || arg.ExportType().Kind() == reflect.Struct {
			cfgMap := arg.Export().(map[string]interface{})
			if u, ok := cfgMap["url"].(string); ok {
				tc.URL = u
			}
			if t, ok := cfgMap["type"].(string); ok {
				tc.Type = t
			}
		} else {
			tc.URL = arg.String()
		}

		res := vm.ToValue(tc).ToObject(vm)
		// Add wg method for chaining
		res.Set("wg", func(innerCall goja.FunctionCall) goja.Value {
			if len(innerCall.Arguments) == 0 {
				return res
			}
			tc.Type = "wg"
			innerArg := innerCall.Arguments[0]
			if innerArg.ExportType().Kind() == reflect.Map {
				innerCfg := innerArg.Export().(map[string]interface{})
				if c, ok := innerCfg["conf"].(string); ok {
					tc.WGConfig = c
				} else if c, ok := innerCfg["wg_config"].(string); ok {
					tc.WGConfig = c
				}
			} else {
				tc.WGConfig = innerArg.String()
			}
			return res
		})
		return res
	})

	connect.Set("wg", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Undefined()
		}
		arg := call.Arguments[0]
		tc := &engine.TunnelConfig{Type: "wg"}

		if arg.ExportType().Kind() == reflect.Map {
			cfgMap := arg.Export().(map[string]interface{})
			if c, ok := cfgMap["conf"].(string); ok {
				tc.WGConfig = c
			} else if c, ok := cfgMap["wg_config"].(string); ok {
				tc.WGConfig = c
			}
			if t, ok := cfgMap["type"].(string); ok {
				tc.Type = t
			}
		} else {
			tc.WGConfig = arg.String()
		}

		res := vm.ToValue(tc).ToObject(vm)
		// Add proxy method for chaining
		res.Set("proxy", func(innerCall goja.FunctionCall) goja.Value {
			if len(innerCall.Arguments) == 0 {
				return res
			}
			innerArg := innerCall.Arguments[0]
			if innerArg.ExportType().Kind() == reflect.Map {
				innerCfg := innerArg.Export().(map[string]interface{})
				if u, ok := innerCfg["url"].(string); ok {
					tc.URL = u
				}
			} else {
				tc.URL = innerArg.String()
			}
			return res
		})
		return res
	})

	connect.Set("ssh", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Undefined()
		}
		arg := call.Arguments[0]
		tc := &engine.TunnelConfig{Type: "ssh", SSH: &engine.SSHConfig{Port: 22}}

		if arg.ExportType().Kind() == reflect.Map {
			cfgMap := arg.Export().(map[string]interface{})
			if v, ok := cfgMap["host"].(string); ok {
				tc.SSH.Host = v
			}
			if v, ok := cfgMap["port"].(int64); ok {
				tc.SSH.Port = int(v)
			}
			if v, ok := cfgMap["user"].(string); ok {
				tc.SSH.User = v
			}
			if v, ok := cfgMap["pass"].(string); ok {
				tc.SSH.Pass = v
			}
			if v, ok := cfgMap["key"].(string); ok {
				tc.SSH.PrivateKey = v
			}
		}

		res := vm.ToValue(tc).ToObject(vm)
		return res
	})

	connect.Set("cgnat", func(call goja.FunctionCall) goja.Value {
		tc := &engine.TunnelConfig{
			Type:  "cgnat",
			CGNAT: &engine.CGNATConfig{AutoDetect: true},
		}

		if len(call.Arguments) > 0 {
			arg := call.Arguments[0]
			if arg.ExportType().Kind() == reflect.Map {
				cfgMap := arg.Export().(map[string]interface{})
				if v, ok := cfgMap["relay"].(string); ok {
					tc.CGNAT.RelayAddr = v
				}
				if v, ok := cfgMap["auth"].(string); ok {
					tc.CGNAT.AuthToken = v
				}
				if v, ok := cfgMap["mikrotik_host"].(string); ok {
					tc.CGNAT.MikroTikHost = v
				}
				if v, ok := cfgMap["mikrotik_user"].(string); ok {
					tc.CGNAT.MikroTikUser = v
				}
				if v, ok := cfgMap["mikrotik_pass"].(string); ok {
					tc.CGNAT.MikroTikPass = v
				}
				if v, ok := cfgMap["auto_detect"].(bool); ok {
					tc.CGNAT.AutoDetect = v
				}
			}
		}

		return vm.ToValue(tc)
	})

	connect.Set("drop", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(&engine.TunnelConfig{Type: "drop"})
	})

	jsCtx["connect"] = connect
}
