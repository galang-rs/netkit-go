package perf

import (
	"runtime"
	"testing"
)

func TestOptimizeCPU_SetsGOMAXPROCS(t *testing.T) {
	OptimizeCPU(0)
	if runtime.GOMAXPROCS(0) != runtime.NumCPU() {
		t.Errorf("GOMAXPROCS should be %d after OptimizeCPU", runtime.NumCPU())
	}
}

func TestOptimalWorkerCount_CPU(t *testing.T) {
	n := OptimalWorkerCount("cpu")
	if n != runtime.NumCPU() {
		t.Errorf("CPU workload should return NumCPU (%d), got %d", runtime.NumCPU(), n)
	}
}

func TestOptimalWorkerCount_IO(t *testing.T) {
	n := OptimalWorkerCount("io")
	expected := runtime.NumCPU() * 4
	if n != expected {
		t.Errorf("IO workload should return NumCPU*4 (%d), got %d", expected, n)
	}
}

func TestOptimalWorkerCount_Mixed(t *testing.T) {
	n := OptimalWorkerCount("mixed")
	expected := runtime.NumCPU() * 2
	if n != expected {
		t.Errorf("Mixed workload should return NumCPU*2 (%d), got %d", expected, n)
	}
}

func TestOptimalWorkerCount_Default(t *testing.T) {
	n := OptimalWorkerCount("unknown")
	if n < 4 {
		t.Errorf("Default should be at least 4, got %d", n)
	}
}

func TestRuntimeStats_HasKeys(t *testing.T) {
	stats := RuntimeStats()
	requiredKeys := []string{"goroutines", "cpu_cores", "alloc_mb", "sys_mb", "heap_objects", "gc_cycles"}
	for _, key := range requiredKeys {
		if _, ok := stats[key]; !ok {
			t.Errorf("RuntimeStats missing key: %s", key)
		}
	}
}

func BenchmarkRuntimeStats(b *testing.B) {
	for i := 0; i < b.N; i++ {
		RuntimeStats()
	}
}
