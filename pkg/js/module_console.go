package js

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/dop251/goja"
)

// RegisterConsole registers the global `console` object on the VM.
// This is called once in NewRuntime because console is always available.
func RegisterConsole(r *Runtime) {
	vm := r.vm
	console := vm.NewObject()

	console.Set("log", func(call goja.FunctionCall) goja.Value {
		parts := make([]string, len(call.Arguments))
		for i, arg := range call.Arguments {
			parts[i] = arg.String()
		}
		logger.Infof("[JS] %s\n", strings.Join(parts, " "))
		return goja.Undefined()
	})

	console.Set("warn", func(call goja.FunctionCall) goja.Value {
		parts := make([]string, len(call.Arguments))
		for i, arg := range call.Arguments {
			parts[i] = arg.String()
		}
		logger.Warnf("[JS WARN] %s\n", strings.Join(parts, " "))
		return goja.Undefined()
	})

	console.Set("error", func(call goja.FunctionCall) goja.Value {
		parts := make([]string, len(call.Arguments))
		for i, arg := range call.Arguments {
			parts[i] = arg.String()
		}
		logger.Errorf("[JS ERROR] %s\n", strings.Join(parts, " "))
		return goja.Undefined()
	})

	console.Set("debug", func(call goja.FunctionCall) goja.Value {
		parts := make([]string, len(call.Arguments))
		for i, arg := range call.Arguments {
			parts[i] = arg.String()
		}
		logger.Printf("[JS DEBUG] %s\n", strings.Join(parts, " "))
		return goja.Undefined()
	})

	console.Set("time", func(call goja.FunctionCall) goja.Value {
		label := "default"
		if len(call.Arguments) > 0 {
			label = call.Arguments[0].String()
		}
		// Store time in global
		vm.Set("__console_timer_"+label, time.Now().UnixMilli())
		return goja.Undefined()
	})

	console.Set("timeEnd", func(call goja.FunctionCall) goja.Value {
		label := "default"
		if len(call.Arguments) > 0 {
			label = call.Arguments[0].String()
		}
		key := "__console_timer_" + label
		v := vm.Get(key)
		if v != nil && !goja.IsUndefined(v) {
			start := v.ToInteger()
			elapsed := time.Now().UnixMilli() - start
			logger.Printf("[JS] %s: %dms\n", label, elapsed)
			vm.Set(key, goja.Undefined())
		}
		return goja.Undefined()
	})

	// Hexdump utility on console
	console.Set("hexdump", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Undefined()
		}
		data := gojaToBytes(call.Arguments[0].Export())
		if data == nil {
			return goja.Undefined()
		}
		logger.Printf("%s\n", hex.Dump(data))
		return goja.Undefined()
	})

	// Packet dump: prints hex + ascii
	console.Set("packetDump", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Undefined()
		}
		data := gojaToBytes(call.Arguments[0].Export())
		if data == nil {
			return goja.Undefined()
		}
		label := "Packet"
		if len(call.Arguments) > 1 {
			label = call.Arguments[1].String()
		}
		logger.Printf("=== %s (%d bytes) ===\n%s", label, len(data), hex.Dump(data))
		return goja.Undefined()
	})

	vm.Set("console", console)
}
