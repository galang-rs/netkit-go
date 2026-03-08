package js

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dop251/goja"
)

// NodeProcess represents a running Node.js process acting as a bridge.
type NodeProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser

	ready     chan struct{}
	exports   map[string]interface{}
	pending   map[int64]chan nodeResponse
	pendingMu sync.Mutex
	callID    atomic.Int64
	vm        *goja.Runtime
	err       error
}

type nodeResponse struct {
	Result interface{} `json:"result"`
	Error  string      `json:"error"`
}

// RegisterNodeModule injects the runNodeJS function into the JS context.
func RegisterNodeModule(r *Runtime, jsCtx map[string]interface{}) {
	vm := r.vm
	runNodeJS := func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Undefined()
		}
		scriptPath := call.Arguments[0].String()

		proc, err := startNodeProcess(vm, scriptPath)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("failed to start node process: %v", err)))
		}

		return proc.ToJSObject()
	}

	jsCtx["runNodeJS"] = runNodeJS
	vm.Set("runNodeJS", runNodeJS)
}

func startNodeProcess(vm *goja.Runtime, scriptPath string) (*NodeProcess, error) {
	_, err := exec.LookPath("node")
	if err != nil {
		return nil, fmt.Errorf("node.js not found in PATH")
	}

	// Calculate bridge path relative to current working directory
	cwd, _ := os.Getwd()
	bridgePath := filepath.Join(cwd, "pkg", "js", "node_bridge.js")

	if _, err := os.Stat(bridgePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("node bridge script not found at %s", bridgePath)
	}

	cmd := exec.Command("node", bridgePath, scriptPath)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr // Pipe stderr for better visibility in logs

	p := &NodeProcess{
		cmd:     cmd,
		stdin:   stdin,
		stdout:  stdout,
		ready:   make(chan struct{}),
		pending: make(map[int64]chan nodeResponse),
		vm:      vm,
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	go p.readLoop()

	// Wait for process to be ready or fail with a timeout
	select {
	case <-p.ready:
		if p.err != nil {
			return nil, p.err
		}
		return p, nil
	case <-time.After(15 * time.Second):
		return nil, fmt.Errorf("node process timed out waiting for ready signal (check if node script exists and is valid)")
	}
}

func (p *NodeProcess) readLoop() {
	scanner := bufio.NewScanner(p.stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NK_NODE_READY:") {
			var meta map[string]interface{}
			err := json.Unmarshal([]byte(line[14:]), &meta)
			if err != nil {
				p.err = err
			}
			p.exports = meta
			close(p.ready)
		} else if strings.HasPrefix(line, "NK_NODE_RES:") {
			var res struct {
				ID     int64       `json:"id"`
				Result interface{} `json:"result"`
				Error  string      `json:"error"`
			}
			err := json.Unmarshal([]byte(line[12:]), &res)
			if err == nil {
				p.pendingMu.Lock()
				if ch, ok := p.pending[res.ID]; ok {
					ch <- nodeResponse{res.Result, res.Error}
					delete(p.pending, res.ID)
				}
				p.pendingMu.Unlock()
			}
		} else if strings.HasPrefix(line, "NK_NODE_ERROR:") {
			p.err = fmt.Errorf("%s", line[14:])
			// Force ready close to signal error
			select {
			case <-p.ready:
			default:
				close(p.ready)
			}
		}
	}

	// If process exits, clear all pending calls with error
	p.pendingMu.Lock()
	for id, ch := range p.pending {
		ch <- nodeResponse{nil, "node process exited prematurely"}
		delete(p.pending, id)
	}
	p.pendingMu.Unlock()

	// Ensure ready channel is closed if it wasn't already (e.g. error before READY)
	select {
	case <-p.ready:
	default:
		if p.err == nil {
			p.err = fmt.Errorf("node process exited before sending ready signal")
		}
		close(p.ready)
	}
}

// ToJSObject creates a Goja object that proxies calls to the Node.js process.
func (p *NodeProcess) ToJSObject() goja.Value {
	obj := p.vm.NewObject()
	for name, meta := range p.exports {
		methodName := name
		if methodName == "__default__" {
			// If it's a direct export, we might want to return it directly,
			// but for now we'll put it in default or ignore if it's an object-style exports.
		}

		m, ok := meta.(map[string]interface{})
		if !ok {
			continue
		}
		t, _ := m["type"].(string)

		if t == "function" {
			obj.Set(methodName, func(call goja.FunctionCall) goja.Value {
				id := p.callID.Add(1)
				args := make([]interface{}, len(call.Arguments))
				for i, a := range call.Arguments {
					args[i] = a.Export()
				}

				respCh := make(chan nodeResponse, 1)
				p.pendingMu.Lock()
				p.pending[id] = respCh
				p.pendingMu.Unlock()

				payload, _ := json.Marshal(map[string]interface{}{
					"id":     id,
					"method": methodName,
					"args":   args,
				})
				_, _ = p.stdin.Write(append(payload, '\n'))

				resp := <-respCh
				if resp.Error != "" {
					panic(p.vm.ToValue(resp.Error))
				}
				return p.vm.ToValue(resp.Result)
			})
		} else {
			obj.Set(methodName, p.vm.ToValue(m["value"]))
		}
	}
	return obj
}
