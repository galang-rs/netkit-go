package js

import (
	"sync"
	"sync/atomic"
)

// RegisterSyncModule injects ctx.Sync into the JS context.
// Provides Mutex, RWMutex, atomic counters, Once, Channel queue, worker pool, event bus.
func RegisterSyncModule(jsCtx map[string]interface{}) {
	jsCtx["Sync"] = map[string]interface{}{
		// NewMutex creates a new mutex object.
		"NewMutex": func() map[string]interface{} {
			mu := &sync.Mutex{}
			return map[string]interface{}{
				"Lock": func() {
					mu.Lock()
				},
				"Unlock": func() {
					mu.Unlock()
				},
			}
		},
		// NewRWMutex creates a new read-write mutex.
		"NewRWMutex": func() map[string]interface{} {
			mu := &sync.RWMutex{}
			return map[string]interface{}{
				"Lock": func() {
					mu.Lock()
				},
				"Unlock": func() {
					mu.Unlock()
				},
				"RLock": func() {
					mu.RLock()
				},
				"RUnlock": func() {
					mu.RUnlock()
				},
			}
		},
		// NewAtomic creates an atomic counter.
		"NewAtomic": func(initial int64) map[string]interface{} {
			v := &atomic.Int64{}
			v.Store(initial)
			return map[string]interface{}{
				"Get": func() int64 {
					return v.Load()
				},
				"Set": func(val int64) {
					v.Store(val)
				},
				"Add": func(delta int64) int64 {
					return v.Add(delta)
				},
				"Incr": func() int64 {
					return v.Add(1)
				},
				"Decr": func() int64 {
					return v.Add(-1)
				},
				"CompareAndSwap": func(old, new int64) bool {
					return v.CompareAndSwap(old, new)
				},
			}
		},
		// NewOnce creates a sync.Once that ensures a function runs exactly once.
		"NewOnce": func() map[string]interface{} {
			once := &sync.Once{}
			return map[string]interface{}{
				"Do": func(fn func()) {
					once.Do(fn)
				},
			}
		},
		// NewChannel creates a buffered channel queue.
		"NewChannel": func(size int) map[string]interface{} {
			if size <= 0 {
				size = 100
			}
			ch := make(chan interface{}, size)
			closed := &atomic.Bool{}
			return map[string]interface{}{
				"Send": func(val interface{}) bool {
					if closed.Load() {
						return false
					}
					select {
					case ch <- val:
						return true
					default:
						return false // channel full
					}
				},
				"Receive": func() interface{} {
					select {
					case v := <-ch:
						return v
					default:
						return nil
					}
				},
				"ReceiveBlocking": func() interface{} {
					v, ok := <-ch
					if !ok {
						return nil
					}
					return v
				},
				"Len": func() int {
					return len(ch)
				},
				"Cap": func() int {
					return cap(ch)
				},
				"Close": func() {
					if !closed.Load() {
						closed.Store(true)
						close(ch)
					}
				},
			}
		},
		// NewWaitGroup creates a WaitGroup.
		"NewWaitGroup": func() map[string]interface{} {
			wg := &sync.WaitGroup{}
			return map[string]interface{}{
				"Add": func(n int) {
					wg.Add(n)
				},
				"Done": func() {
					wg.Done()
				},
				"Wait": func() {
					wg.Wait()
				},
			}
		},
		// NewWorkerPool creates a pool of goroutine workers.
		"NewWorkerPool": func(workerCount int) map[string]interface{} {
			if workerCount <= 0 {
				workerCount = 4
			}
			tasks := make(chan func(), 1000)
			done := make(chan struct{})
			closed := &atomic.Bool{}

			// Start workers
			wg := &sync.WaitGroup{}
			for i := 0; i < workerCount; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case task, ok := <-tasks:
							if !ok {
								return
							}
							func() {
								defer func() { recover() }()
								task()
							}()
						case <-done:
							return
						}
					}
				}()
			}

			return map[string]interface{}{
				"Submit": func(fn func()) bool {
					if closed.Load() {
						return false
					}
					select {
					case tasks <- fn:
						return true
					default:
						return false // queue full
					}
				},
				"Stop": func() {
					if !closed.Load() {
						closed.Store(true)
						close(done)
					}
				},
				"QueueSize": func() int {
					return len(tasks)
				},
			}
		},
		// NewEventBus creates a publish/subscribe event bus.
		"NewEventBus": func() map[string]interface{} {
			mu := &sync.RWMutex{}
			subscribers := make(map[string][]func(interface{}))
			return map[string]interface{}{
				"On": func(event string, handler func(interface{})) {
					mu.Lock()
					subscribers[event] = append(subscribers[event], handler)
					mu.Unlock()
				},
				"Emit": func(event string, data interface{}) {
					mu.RLock()
					handlers := subscribers[event]
					mu.RUnlock()
					for _, h := range handlers {
						func() {
							defer func() { recover() }()
							h(data)
						}()
					}
				},
				"Off": func(event string) {
					mu.Lock()
					delete(subscribers, event)
					mu.Unlock()
				},
				"Events": func() []string {
					mu.RLock()
					defer mu.RUnlock()
					var events []string
					for k := range subscribers {
						events = append(events, k)
					}
					return events
				},
			}
		},
		// NewMap creates a concurrent-safe map.
		"NewMap": func() map[string]interface{} {
			m := &sync.Map{}
			return map[string]interface{}{
				"Set": func(key string, val interface{}) {
					m.Store(key, val)
				},
				"Get": func(key string) interface{} {
					v, ok := m.Load(key)
					if !ok {
						return nil
					}
					return v
				},
				"Delete": func(key string) {
					m.Delete(key)
				},
				"Has": func(key string) bool {
					_, ok := m.Load(key)
					return ok
				},
				"Keys": func() []string {
					var keys []string
					m.Range(func(k, v interface{}) bool {
						if s, ok := k.(string); ok {
							keys = append(keys, s)
						}
						return true
					})
					return keys
				},
			}
		},
	}
}
