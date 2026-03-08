package js

import (
	"sync"
	"sync/atomic"
	"time"
)

// trafficController manages rate limiting, throttling, and flood detection.
type trafficController struct {
	mu              sync.Mutex
	rateLimiters    map[string]*rateLimiter
	connCount       atomic.Int64
	maxConns        int64
	bandwidthBytes  atomic.Int64
	throttleBPS     int64 // bytes per second, 0 = unlimited
	floodThreshold  int64 // packets per second to trigger flood
	floodCounter    atomic.Int64
	floodResetTimer *time.Ticker
}

type rateLimiter struct {
	tokens    float64
	maxTokens float64
	refillBPS float64 // tokens per second
	lastTime  time.Time
	mu        sync.Mutex
}

func (rl *rateLimiter) allow(n int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(rl.lastTime).Seconds()
	rl.tokens += elapsed * rl.refillBPS
	if rl.tokens > rl.maxTokens {
		rl.tokens = rl.maxTokens
	}
	rl.lastTime = now
	if rl.tokens >= float64(n) {
		rl.tokens -= float64(n)
		return true
	}
	return false
}

var globalTraffic = &trafficController{
	rateLimiters: make(map[string]*rateLimiter),
	maxConns:     10000,
}

// RegisterTrafficModule injects ctx.Traffic into the JS context.
func RegisterTrafficModule(jsCtx map[string]interface{}) {
	tc := globalTraffic

	jsCtx["Traffic"] = map[string]interface{}{
		// RateLimit checks if an operation is allowed under the given rate limit.
		// key: identifier (e.g., IP), rps: requests per second
		"RateLimit": func(key string, rps float64) bool {
			tc.mu.Lock()
			rl, ok := tc.rateLimiters[key]
			if !ok {
				rl = &rateLimiter{
					tokens:    rps,
					maxTokens: rps * 2, // burst = 2x
					refillBPS: rps,
					lastTime:  time.Now(),
				}
				tc.rateLimiters[key] = rl
			}
			tc.mu.Unlock()
			return rl.allow(1)
		},

		// RateLimitN checks if N operations are allowed.
		"RateLimitN": func(key string, rps float64, n int) bool {
			tc.mu.Lock()
			rl, ok := tc.rateLimiters[key]
			if !ok {
				rl = &rateLimiter{
					tokens:    rps,
					maxTokens: rps * 2,
					refillBPS: rps,
					lastTime:  time.Now(),
				}
				tc.rateLimiters[key] = rl
			}
			tc.mu.Unlock()
			return rl.allow(n)
		},

		// SetMaxConnections sets the concurrent connection limit.
		"SetMaxConnections": func(max int64) {
			tc.maxConns = max
		},

		// ConnectionAllowed checks if a new connection is allowed.
		"ConnectionAllowed": func() bool {
			return tc.connCount.Load() < tc.maxConns
		},

		// IncrementConnections increments active connection count.
		"IncrementConnections": func() {
			tc.connCount.Add(1)
		},

		// DecrementConnections decrements active connection count.
		"DecrementConnections": func() {
			tc.connCount.Add(-1)
		},

		// ActiveConnections returns current active connection count.
		"ActiveConnections": func() int64 {
			return tc.connCount.Load()
		},

		// SetThrottle sets bandwidth limit in bytes per second (0 = unlimited).
		"SetThrottle": func(bps int64) {
			tc.throttleBPS = bps
		},

		// GetThrottle returns the current throttle setting.
		"GetThrottle": func() int64 {
			return tc.throttleBPS
		},

		// ThrottleCheck checks if data should be delayed based on bandwidth.
		"ThrottleCheck": func(dataSize int64) bool {
			if tc.throttleBPS <= 0 {
				return true // no throttle
			}
			return tc.bandwidthBytes.Load() < tc.throttleBPS
		},

		// AddBandwidth records bandwidth usage.
		"AddBandwidth": func(bytes int64) {
			tc.bandwidthBytes.Add(bytes)
		},

		// SetFloodThreshold sets the packets-per-second threshold for flood detection.
		"SetFloodThreshold": func(pps int64) {
			tc.floodThreshold = pps
			// Start or restart the reset timer
			if tc.floodResetTimer != nil {
				tc.floodResetTimer.Stop()
			}
			tc.floodResetTimer = time.NewTicker(1 * time.Second)
			go func() {
				for range tc.floodResetTimer.C {
					tc.floodCounter.Store(0)
				}
			}()
		},

		// FloodCheck increments counter and returns true if flood detected.
		"FloodCheck": func() bool {
			count := tc.floodCounter.Add(1)
			if tc.floodThreshold <= 0 {
				return false
			}
			return count > tc.floodThreshold
		},

		// ResetRateLimit resets a specific rate limiter.
		"ResetRateLimit": func(key string) {
			tc.mu.Lock()
			delete(tc.rateLimiters, key)
			tc.mu.Unlock()
		},

		// ResetAllRateLimits clears all rate limiters.
		"ResetAllRateLimits": func() {
			tc.mu.Lock()
			tc.rateLimiters = make(map[string]*rateLimiter)
			tc.mu.Unlock()
		},
	}
}
