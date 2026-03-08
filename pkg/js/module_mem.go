package js

import (
	"context"
	"log"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/bacot120211/netkit-go/pkg/mem"
)

// globalMemReducer is the singleton memory reducer.
var globalMemReducer mem.Reducer

func init() {
	globalMemReducer = mem.New()
}

// RegisterMemModule injects ctx.Mem into the JS context.
// Provides memory reduction, GC control, and memory stats.
func RegisterMemModule(jsCtx map[string]interface{}) {
	reducer := globalMemReducer

	jsCtx["Mem"] = map[string]interface{}{
		// Reduce performs system-level memory optimization.
		// On Windows: trims working set, purges standby/modified lists, compacts heap.
		// On other OS: calls debug.FreeOSMemory().
		"Reduce": func() {
			reducer.Reduce()
		},

		// StartPeriodic starts periodic memory reduction at given interval (ms).
		"StartPeriodic": func(intervalMs int64) {
			if intervalMs <= 0 {
				intervalMs = 60000 // default 1 minute
			}
			ctx := context.Background()
			reducer.StartPeriodic(ctx, time.Duration(intervalMs)*time.Millisecond)
			log.Printf("[JS] Memory periodic reducer started (every %dms)", intervalMs)
		},

		// GC triggers Go garbage collection.
		"GC": func() {
			runtime.GC()
		},

		// FreeOSMemory releases memory back to the OS.
		"FreeOSMemory": func() {
			debug.FreeOSMemory()
		},

		// SetGCPercent sets the Go GC target percentage. Returns the previous value.
		"SetGCPercent": func(percent int) int {
			return debug.SetGCPercent(percent)
		},

		// Stats returns current Go runtime memory stats.
		"Stats": func() map[string]interface{} {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			return map[string]interface{}{
				"allocMB":        float64(m.Alloc) / 1024 / 1024,
				"totalAllocMB":   float64(m.TotalAlloc) / 1024 / 1024,
				"sysMB":          float64(m.Sys) / 1024 / 1024,
				"heapAllocMB":    float64(m.HeapAlloc) / 1024 / 1024,
				"heapSysMB":      float64(m.HeapSys) / 1024 / 1024,
				"heapIdleMB":     float64(m.HeapIdle) / 1024 / 1024,
				"heapInuseMB":    float64(m.HeapInuse) / 1024 / 1024,
				"heapReleasedMB": float64(m.HeapReleased) / 1024 / 1024,
				"heapObjects":    m.HeapObjects,
				"stackInuseMB":   float64(m.StackInuse) / 1024 / 1024,
				"numGC":          m.NumGC,
				"numGoroutine":   runtime.NumGoroutine(),
				"gcPauseNs":      m.PauseNs[(m.NumGC+255)%256],
			}
		},

		// HeapAlloc returns current heap allocation in MB.
		"HeapAlloc": func() float64 {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			return float64(m.HeapAlloc) / 1024 / 1024
		},

		// NumGoroutine returns the number of active goroutines.
		"NumGoroutine": func() int {
			return runtime.NumGoroutine()
		},

		// SetMemoryLimit sets the Go runtime soft memory limit in MB (0 to disable).
		"SetMemoryLimit": func(mb int64) int64 {
			if mb <= 0 {
				return int64(debug.SetMemoryLimit(-1)) / 1024 / 1024
			}
			old := debug.SetMemoryLimit(mb * 1024 * 1024)
			return old / 1024 / 1024
		},

		// SystemStats returns system-wide memory metrics.
		"SystemStats": func() (map[string]interface{}, error) {
			stats, err := reducer.GetSystemStats()
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"totalPhysMB":     stats.TotalPhysMB,
				"availPhysMB":     stats.AvailPhysMB,
				"totalVirtualMB":  stats.TotalVirtualMB,
				"availVirtualMB":  stats.AvailVirtualMB,
				"memoryLoad":      stats.MemoryLoad,
				"totalPageFileMB": stats.TotalPageFileMB,
				"availPageFileMB": stats.AvailPageFileMB,
			}, nil
		},
	}
}
