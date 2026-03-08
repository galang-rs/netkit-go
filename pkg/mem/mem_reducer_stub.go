//go:build !windows

package mem

import (
	"context"
	"runtime/debug"
	"time"
)

type StubReducer struct{}

func getReducer() Reducer {
	return &StubReducer{}
}

// Reduce is a stub for non-Windows platforms.
// It uses standard Go debug.FreeOSMemory() as a fallback.
func (r *StubReducer) Reduce() {
	debug.FreeOSMemory()
}

// StartPeriodic is a stub for non-Windows platforms.
func (r *StubReducer) StartPeriodic(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.Reduce()
			}
		}
	}()
}

func (r *StubReducer) GetSystemStats() (*SystemStats, error) {
	return &SystemStats{}, nil
}
