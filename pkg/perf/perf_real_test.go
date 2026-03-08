package perf

import (
	"testing"
)

func TestPerfReal_ProductFlow(t *testing.T) {
	// 1. Run Optimization
	OptimizeCPU(0)

	// 2. Check Stats
	stats := RuntimeStats()
	if stats["cpu_cores"].(int) < 1 {
		t.Errorf("Invalid CPU core count")
	}
	// alloc_mb is uint64 in some versions, but let's just check it's present
	if _, ok := stats["alloc_mb"]; !ok {
		t.Errorf("alloc_mb missing from stats")
	}
	t.Logf("Perf Stats verified! Goroutines: %v, Memory: %v MB", stats["goroutines"], stats["alloc_mb"])
}
