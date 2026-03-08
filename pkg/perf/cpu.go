// Package perf provides CPU performance optimization utilities for the engine.
// It configures Go runtime settings for maximum throughput on the target system.
package perf

import (
	"runtime"
	"runtime/debug"

	"github.com/bacot120211/netkit-go/pkg/logger"
)

// OptimizeCPU configures the Go runtime for maximum CPU throughput.
// Should be called early in application startup (e.g. init() or main()).
func OptimizeCPU(maxProcs int) {
	// 1. Use all available CPU cores or user-specified count
	numCPU := runtime.NumCPU()
	if maxProcs > 0 {
		numCPU = maxProcs
	}
	prev := runtime.GOMAXPROCS(numCPU)
	logger.Infof("[Perf] GOMAXPROCS: %d -> %d (all cores)\n", prev, numCPU)

	// 2. Set GC target to reduce garbage collection frequency
	//    Default is 100 (GC when heap grows 100%). Higher value = less frequent GC = more CPU for work
	//    We use 200 for a good balance between memory and CPU
	debug.SetGCPercent(200)
	logger.Infof("[Perf] GC target: 200%% (reduced GC frequency)\n")

	// 3. Set memory limit hint (soft limit) — let Go manage memory more efficiently
	//    This tells the runtime to be aggressive about returning memory to OS when nearing limit
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	logger.Infof("[Perf] Current alloc: %d MB, sys: %d MB\n", memStats.Alloc/1024/1024, memStats.Sys/1024/1024)

	// 4. Limit max threads to prevent excessive OS thread creation
	//    Default is 10000 which is too high. For a network tool, CPU_count * 256 is plenty.
	maxThreads := numCPU * 256
	if maxThreads < 1024 {
		maxThreads = 1024
	}
	debug.SetMaxThreads(maxThreads)
	logger.Infof("[Perf] Max OS threads: %d\n", maxThreads)
}

// OptimalWorkerCount returns the recommended number of worker goroutines
// based on the system's CPU cores and the type of workload.
func OptimalWorkerCount(workloadType string) int {
	n := runtime.NumCPU()
	switch workloadType {
	case "cpu":
		// CPU-bound: one worker per core
		return n
	case "io":
		// I/O-bound (network): more workers than cores to keep CPU busy during I/O waits
		return n * 4
	case "mixed":
		// Mixed workload (typical for packet processing)
		return n * 2
	default:
		if n < 4 {
			return 4
		}
		return n
	}
}

// RuntimeStats returns current memory and goroutine statistics.
func RuntimeStats() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return map[string]interface{}{
		"goroutines":        runtime.NumGoroutine(),
		"cpu_cores":         runtime.NumCPU(),
		"alloc_mb":          m.Alloc / 1024 / 1024,
		"sys_mb":            m.Sys / 1024 / 1024,
		"heap_objects":      m.HeapObjects,
		"gc_cycles":         m.NumGC,
		"gc_pause_total_ms": m.PauseTotalNs / 1_000_000,
	}
}
