package mem

import (
	"context"
	"testing"
	"time"
)

func TestNew_ReturnsReducer(t *testing.T) {
	r := New()
	if r == nil {
		t.Fatal("New() should return a non-nil Reducer")
	}
}

func TestReducer_Reduce_NoPanic(t *testing.T) {
	r := New()
	// Reduce should not panic on any platform
	r.Reduce()
}

func TestReducer_Reduce_Multiple(t *testing.T) {
	r := New()
	// Multiple calls should not panic
	for i := 0; i < 5; i++ {
		r.Reduce()
	}
}

func TestReducer_StartPeriodic_NoPanic(t *testing.T) {
	r := New()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	r.StartPeriodic(ctx, 100*time.Millisecond)

	// Wait for periodic to trigger at least once
	time.Sleep(300 * time.Millisecond)
}

func TestReducer_StartPeriodic_CancelsCleanly(t *testing.T) {
	r := New()
	ctx, cancel := context.WithCancel(context.Background())

	r.StartPeriodic(ctx, 50*time.Millisecond)
	time.Sleep(200 * time.Millisecond)

	// Cancel should stop the goroutine
	cancel()
	time.Sleep(100 * time.Millisecond)
	// No goroutine leak — if we get here without hanging, the test passes
}

func TestReducer_GetSystemStats(t *testing.T) {
	r := New()
	stats, err := r.GetSystemStats()
	if err != nil {
		t.Fatalf("GetSystemStats failed: %v", err)
	}
	if stats == nil {
		t.Fatal("stats should not be nil")
	}
	// On Windows, these should be non-zero
	t.Logf("Total Phys: %d MB, Avail: %d MB, Load: %d%%",
		stats.TotalPhysMB, stats.AvailPhysMB, stats.MemoryLoad)
}
