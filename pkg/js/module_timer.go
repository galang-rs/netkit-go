package js

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/dop251/goja"
)

// timerManager manages setTimeout / setInterval lifecycle.
type timerManager struct {
	mu      sync.Mutex
	nextID  atomic.Int64
	timers  map[int64]*time.Timer
	tickers map[int64]*time.Ticker
}

var globalTimerManager = &timerManager{
	timers:  make(map[int64]*time.Timer),
	tickers: make(map[int64]*time.Ticker),
}

// RegisterTimers registers global setTimeout, setInterval, clearTimeout, clearInterval, Sleep.
func RegisterTimers(r *Runtime) {
	vm := r.vm
	tm := globalTimerManager

	// Sleep(ms) — blocking
	vm.Set("Sleep", func(ms int64) {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	})

	// setTimeout(fn, ms) -> id
	vm.Set("setTimeout", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			return goja.Undefined()
		}
		fn, ok := goja.AssertFunction(call.Arguments[0])
		if !ok {
			return goja.Undefined()
		}
		ms := call.Arguments[1].ToInteger()
		id := tm.nextID.Add(1)

		timer := time.AfterFunc(time.Duration(ms)*time.Millisecond, func() {
			r.Lock()
			fn(goja.Undefined())
			r.Unlock()
			tm.mu.Lock()
			delete(tm.timers, id)
			tm.mu.Unlock()
		})

		tm.mu.Lock()
		tm.timers[id] = timer
		tm.mu.Unlock()

		return vm.ToValue(id)
	})

	// clearTimeout(id)
	vm.Set("clearTimeout", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Undefined()
		}
		id := call.Arguments[0].ToInteger()
		tm.mu.Lock()
		if t, ok := tm.timers[id]; ok {
			t.Stop()
			delete(tm.timers, id)
		}
		tm.mu.Unlock()
		return goja.Undefined()
	})

	// setInterval(fn, ms) -> id
	vm.Set("setInterval", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			return goja.Undefined()
		}
		fn, ok := goja.AssertFunction(call.Arguments[0])
		if !ok {
			return goja.Undefined()
		}
		ms := call.Arguments[1].ToInteger()
		id := tm.nextID.Add(1)

		ticker := time.NewTicker(time.Duration(ms) * time.Millisecond)
		tm.mu.Lock()
		tm.tickers[id] = ticker
		tm.mu.Unlock()

		go func() {
			for range ticker.C {
				r.Lock()
				fn(goja.Undefined())
				r.Unlock()
			}
		}()

		return vm.ToValue(id)
	})

	// clearInterval(id)
	vm.Set("clearInterval", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Undefined()
		}
		id := call.Arguments[0].ToInteger()
		tm.mu.Lock()
		if t, ok := tm.tickers[id]; ok {
			t.Stop()
			delete(tm.tickers, id)
		}
		tm.mu.Unlock()
		return goja.Undefined()
	})
}
