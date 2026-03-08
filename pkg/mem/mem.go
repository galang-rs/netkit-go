package mem

import (
	"context"
	"time"
)

// SystemStats contains system-wide memory metrics.
type SystemStats struct {
	TotalPhysMB     uint64
	AvailPhysMB     uint64
	TotalVirtualMB  uint64
	AvailVirtualMB  uint64
	MemoryLoad      uint32 // Percentage of physical memory in use
	TotalPageFileMB uint64
	AvailPageFileMB uint64
}

// Reducer defines the interface for memory optimization.
type Reducer interface {
	Reduce()
	StartPeriodic(ctx context.Context, interval time.Duration)
	GetSystemStats() (*SystemStats, error)
}

// New returns a platform-specific memory reducer.
func New() Reducer {
	return getReducer()
}
