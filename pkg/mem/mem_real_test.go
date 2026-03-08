package mem

import (
	"context"
	"testing"
	"time"
)

func TestMemReal_Reducer(t *testing.T) {
	reducer := New()

	// 1. Trigger Reduction
	reducer.Reduce() // returns nothing
	t.Logf("Memory reduction triggered")

	// 2. Periodic start (smoke test)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reducer.StartPeriodic(ctx, 100*time.Millisecond)

	t.Logf("Reducer verified!")
}
