package js

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dop251/goja"
)

// scriptRule represents a managed JS rule with metadata.
type scriptRule struct {
	ID       string
	Name     string
	Priority int
	Enabled  bool
	Tags     []string
	Timeout  time.Duration
	MemLimit int64
}

// scriptManager manages the lifecycle of JS rules.
type scriptManager struct {
	mu    sync.RWMutex
	rules map[string]*scriptRule
}

var globalScriptManager = &scriptManager{
	rules: make(map[string]*scriptRule),
}

// RegisterScriptModule injects ctx.Script into the JS context and global Runtime.spawn.
func RegisterScriptModule(r *Runtime, jsCtx map[string]interface{}) {
	vm := r.vm
	sm := globalScriptManager

	// Runtime.spawn — run a function in a background goroutine
	runtime := vm.NewObject()
	var spawnCount atomic.Int64

	runtime.Set("spawn", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Undefined()
		}
		fn, ok := goja.AssertFunction(call.Arguments[0])
		if !ok {
			return goja.Undefined()
		}
		id := spawnCount.Add(1)
		go func() {
			defer func() { recover() }()
			r.Lock()
			fn(goja.Undefined())
			r.Unlock()
		}()
		return vm.ToValue(id)
	})

	// Runtime.spawnWithTimeout — spawn with a deadline
	runtime.Set("spawnWithTimeout", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			return goja.Undefined()
		}
		fn, ok := goja.AssertFunction(call.Arguments[0])
		if !ok {
			return goja.Undefined()
		}
		timeoutMs := call.Arguments[1].ToInteger()
		id := spawnCount.Add(1)

		go func() {
			defer func() { recover() }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
			defer cancel()

			done := make(chan struct{})
			go func() {
				defer func() { recover() }()
				r.Lock()
				fn(goja.Undefined())
				r.Unlock()
				close(done)
			}()

			select {
			case <-done:
			case <-ctx.Done():
				fmt.Printf("[JS] spawn %d timed out after %dms\n", id, timeoutMs)
			}
		}()

		return vm.ToValue(id)
	})

	vm.Set("Runtime", runtime)

	// ctx.Script — rule management
	jsCtx["Script"] = map[string]interface{}{
		// RegisterRule registers a named rule with metadata.
		"RegisterRule": func(id, name string, priority int, tags []interface{}) {
			sm.mu.Lock()
			defer sm.mu.Unlock()
			var tagStrs []string
			for _, t := range tags {
				tagStrs = append(tagStrs, fmt.Sprintf("%v", t))
			}
			sm.rules[id] = &scriptRule{
				ID:       id,
				Name:     name,
				Priority: priority,
				Enabled:  true,
				Tags:     tagStrs,
				Timeout:  5 * time.Second,
			}
		},

		// EnableRule enables a rule by ID.
		"EnableRule": func(id string) bool {
			sm.mu.Lock()
			defer sm.mu.Unlock()
			if r, ok := sm.rules[id]; ok {
				r.Enabled = true
				return true
			}
			return false
		},

		// DisableRule disables a rule by ID.
		"DisableRule": func(id string) bool {
			sm.mu.Lock()
			defer sm.mu.Unlock()
			if r, ok := sm.rules[id]; ok {
				r.Enabled = false
				return true
			}
			return false
		},

		// IsEnabled checks if a rule is enabled.
		"IsEnabled": func(id string) bool {
			sm.mu.RLock()
			defer sm.mu.RUnlock()
			if r, ok := sm.rules[id]; ok {
				return r.Enabled
			}
			return false
		},

		// SetPriority sets the priority of a rule.
		"SetPriority": func(id string, priority int) {
			sm.mu.Lock()
			defer sm.mu.Unlock()
			if r, ok := sm.rules[id]; ok {
				r.Priority = priority
			}
		},

		// SetTimeout sets the execution timeout for a rule.
		"SetTimeout": func(id string, ms int64) {
			sm.mu.Lock()
			defer sm.mu.Unlock()
			if r, ok := sm.rules[id]; ok {
				r.Timeout = time.Duration(ms) * time.Millisecond
			}
		},

		// SetMemLimit sets the memory limit for a rule.
		"SetMemLimit": func(id string, mb int64) {
			sm.mu.Lock()
			defer sm.mu.Unlock()
			if r, ok := sm.rules[id]; ok {
				r.MemLimit = mb
			}
		},

		// ListRules returns all registered rules.
		"ListRules": func() []map[string]interface{} {
			sm.mu.RLock()
			defer sm.mu.RUnlock()
			var result []map[string]interface{}
			for _, r := range sm.rules {
				result = append(result, map[string]interface{}{
					"id":       r.ID,
					"name":     r.Name,
					"priority": r.Priority,
					"enabled":  r.Enabled,
					"tags":     r.Tags,
					"timeout":  r.Timeout.Milliseconds(),
					"memLimit": r.MemLimit,
				})
			}
			return result
		},

		// RemoveRule removes a rule.
		"RemoveRule": func(id string) {
			sm.mu.Lock()
			delete(sm.rules, id)
			sm.mu.Unlock()
		},

		// GetRulesByTag returns rules matching a tag.
		"GetRulesByTag": func(tag string) []map[string]interface{} {
			sm.mu.RLock()
			defer sm.mu.RUnlock()
			var result []map[string]interface{}
			for _, r := range sm.rules {
				for _, t := range r.Tags {
					if t == tag {
						result = append(result, map[string]interface{}{
							"id":       r.ID,
							"name":     r.Name,
							"priority": r.Priority,
							"enabled":  r.Enabled,
						})
						break
					}
				}
			}
			return result
		},
	}
}
