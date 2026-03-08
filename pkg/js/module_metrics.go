package js

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

// metricsStore holds all global metrics.
type metricsStore struct {
	mu              sync.RWMutex
	totalPackets    atomic.Int64
	totalBytes      atomic.Int64
	droppedPackets  atomic.Int64
	modifiedPackets atomic.Int64
	activeConns     atomic.Int64
	startTime       time.Time
	custom          map[string]*atomic.Int64
}

var globalMetrics = &metricsStore{
	startTime: time.Now(),
	custom:    make(map[string]*atomic.Int64),
}

// RegisterMetricsModule injects ctx.Metrics into the JS context.
func RegisterMetricsModule(jsCtx map[string]interface{}) {
	m := globalMetrics

	jsCtx["Metrics"] = map[string]interface{}{
		// IncrPackets increments total packet counter.
		"IncrPackets": func(n int64) {
			m.totalPackets.Add(n)
		},
		// IncrBytes increments total byte counter.
		"IncrBytes": func(n int64) {
			m.totalBytes.Add(n)
		},
		// IncrDropped increments dropped packet counter.
		"IncrDropped": func() {
			m.droppedPackets.Add(1)
		},
		// IncrModified increments modified packet counter.
		"IncrModified": func() {
			m.modifiedPackets.Add(1)
		},
		// IncrConns increments active connection counter.
		"IncrConns": func() {
			m.activeConns.Add(1)
		},
		// DecrConns decrements active connection counter.
		"DecrConns": func() {
			m.activeConns.Add(-1)
		},
		// GetPackets returns total packet count.
		"GetPackets": func() int64 {
			return m.totalPackets.Load()
		},
		// GetBytes returns total byte count.
		"GetBytes": func() int64 {
			return m.totalBytes.Load()
		},
		// GetDropped returns dropped packet count.
		"GetDropped": func() int64 {
			return m.droppedPackets.Load()
		},
		// GetModified returns modified packet count.
		"GetModified": func() int64 {
			return m.modifiedPackets.Load()
		},
		// GetActiveConns returns active connection count.
		"GetActiveConns": func() int64 {
			return m.activeConns.Load()
		},
		// Uptime returns engine uptime in seconds.
		"Uptime": func() int64 {
			return int64(time.Since(m.startTime).Seconds())
		},
		// UptimeMs returns engine uptime in milliseconds.
		"UptimeMs": func() int64 {
			return time.Since(m.startTime).Milliseconds()
		},
		// Bandwidth returns packets-per-second estimate.
		"PPS": func() float64 {
			elapsed := time.Since(m.startTime).Seconds()
			if elapsed == 0 {
				return 0
			}
			return float64(m.totalPackets.Load()) / elapsed
		},
		// BPS returns bytes-per-second estimate.
		"BPS": func() float64 {
			elapsed := time.Since(m.startTime).Seconds()
			if elapsed == 0 {
				return 0
			}
			return float64(m.totalBytes.Load()) / elapsed
		},
		// SetCustom sets a custom counter.
		"SetCustom": func(name string, val int64) {
			m.mu.Lock()
			if _, ok := m.custom[name]; !ok {
				m.custom[name] = &atomic.Int64{}
			}
			m.custom[name].Store(val)
			m.mu.Unlock()
		},
		// IncrCustom increments a custom counter.
		"IncrCustom": func(name string, n int64) {
			m.mu.Lock()
			if _, ok := m.custom[name]; !ok {
				m.custom[name] = &atomic.Int64{}
			}
			m.mu.Unlock()
			m.custom[name].Add(n)
		},
		// GetCustom returns a custom counter value.
		"GetCustom": func(name string) int64 {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if c, ok := m.custom[name]; ok {
				return c.Load()
			}
			return 0
		},
		// Snapshot returns all metrics as a map (for JSON export).
		"Snapshot": func() map[string]interface{} {
			result := map[string]interface{}{
				"totalPackets":    m.totalPackets.Load(),
				"totalBytes":      m.totalBytes.Load(),
				"droppedPackets":  m.droppedPackets.Load(),
				"modifiedPackets": m.modifiedPackets.Load(),
				"activeConns":     m.activeConns.Load(),
				"uptimeSeconds":   int64(time.Since(m.startTime).Seconds()),
				"pps":             float64(m.totalPackets.Load()) / time.Since(m.startTime).Seconds(),
				"bps":             float64(m.totalBytes.Load()) / time.Since(m.startTime).Seconds(),
			}
			m.mu.RLock()
			custom := make(map[string]int64)
			for k, v := range m.custom {
				custom[k] = v.Load()
			}
			m.mu.RUnlock()
			result["custom"] = custom
			return result
		},
		// JSON returns all metrics as JSON string.
		"JSON": func() string {
			snap := map[string]interface{}{
				"totalPackets":    m.totalPackets.Load(),
				"totalBytes":      m.totalBytes.Load(),
				"droppedPackets":  m.droppedPackets.Load(),
				"modifiedPackets": m.modifiedPackets.Load(),
				"activeConns":     m.activeConns.Load(),
				"uptimeSeconds":   int64(time.Since(m.startTime).Seconds()),
			}
			b, _ := json.Marshal(snap)
			return string(b)
		},
		// Reset clears all metrics.
		"Reset": func() {
			m.totalPackets.Store(0)
			m.totalBytes.Store(0)
			m.droppedPackets.Store(0)
			m.modifiedPackets.Store(0)
			m.activeConns.Store(0)
			m.startTime = time.Now()
			m.mu.Lock()
			m.custom = make(map[string]*atomic.Int64)
			m.mu.Unlock()
		},
	}
}
