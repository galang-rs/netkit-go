package js

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/bacot120211/netkit-go/pkg/session"
)

// SessionStats tracks per-session packet and byte counters.
type SessionStats struct {
	PacketCount atomic.Int64
	ByteCount   atomic.Int64
	StartTime   time.Time
}

// globalSessionStats stores stats keyed by session ID.
var globalSessionStats = struct {
	mu sync.RWMutex
	m  map[string]*SessionStats
}{
	m: make(map[string]*SessionStats),
}

// RegisterSessionModule injects enriched ctx.Session into the JS context.
func RegisterSessionModule(jsCtx map[string]interface{}, sess *session.Session) {
	if sess == nil {
		return
	}

	// Get or create stats
	globalSessionStats.mu.RLock()
	stats, ok := globalSessionStats.m[sess.ID]
	globalSessionStats.mu.RUnlock()

	if !ok {
		globalSessionStats.mu.Lock()
		// Double check to avoid race between RUnlock and Lock
		stats, ok = globalSessionStats.m[sess.ID]
		if !ok {
			stats = &SessionStats{StartTime: time.Now()}
			globalSessionStats.m[sess.ID] = stats
		}
		globalSessionStats.mu.Unlock()
	}
	stats.PacketCount.Add(1)

	jsCtx["Session"] = map[string]interface{}{
		"ID":   sess.ID,
		"Type": sess.Type,
		"Src":  sess.Source,
		"Dst":  sess.Dest,
		// Set persists a key-value pair on the session.
		"Set": func(key string, val interface{}) {
			sess.Data.Store(key, val)
		},
		// Get retrieves a value by key.
		"Get": func(key string) interface{} {
			v, ok := sess.Data.Load(key)
			if !ok {
				return nil
			}
			return v
		},
		// Delete removes a key from session data.
		"Delete": func(key string) {
			sess.Data.Delete(key)
		},
		// Has checks if a key exists.
		"Has": func(key string) bool {
			_, ok := sess.Data.Load(key)
			return ok
		},
		// Keys returns all stored keys.
		"Keys": func() []string {
			var keys []string
			sess.Data.Range(func(k, v interface{}) bool {
				if s, ok := k.(string); ok {
					keys = append(keys, s)
				}
				return true
			})
			return keys
		},
		// PacketCount returns total packets seen on this session.
		"PacketCount": func() int64 {
			return stats.PacketCount.Load()
		},
		// ByteCount returns total bytes seen on this session.
		"ByteCount": func() int64 {
			return stats.ByteCount.Load()
		},
		// AddBytes increments the byte counter.
		"AddBytes": func(n int64) {
			stats.ByteCount.Add(n)
		},
		// Duration returns how long the session has been active (ms).
		"Duration": func() int64 {
			return time.Since(stats.StartTime).Milliseconds()
		},
		// StartTime returns session start as unix millis.
		"StartTime": func() int64 {
			return stats.StartTime.UnixMilli()
		},
		// Metadata returns the session metadata map.
		"Metadata": sess.Metadata,
	}
}
