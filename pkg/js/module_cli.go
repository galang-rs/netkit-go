package js

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/dop251/goja"
)

// RegisterCLIModule injects the global `CLI` function into the VM.
func RegisterCLIModule(r *Runtime, jsCtx map[string]interface{}) {
	vm := r.vm
	jsCtx["CLI"] = func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return vm.ToValue(map[string]interface{}{
				"error": "CLI requires a command string",
			})
		}

		cmdStr := call.Arguments[0].String()
		parts := strings.Fields(cmdStr)
		if len(parts) == 0 {
			return vm.ToValue(map[string]interface{}{
				"error": "empty command",
			})
		}

		cmd := exec.Command(parts[0], parts[1:]...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()

		result := map[string]interface{}{
			"stdout":   stdout.String(),
			"stderr":   stderr.String(),
			"exitCode": 0,
		}

		if err != nil {
			result["error"] = err.Error()
			if exitErr, ok := err.(*exec.ExitError); ok {
				result["exitCode"] = exitErr.ExitCode()
			} else {
				result["exitCode"] = -1
			}
		}

		return vm.ToValue(result)
	}
}
