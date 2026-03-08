package js

import (
	"math/rand"
	"time"
)

// RegisterTestSimModule injects ctx.Sim into the JS context.
// Provides network simulation tools for testing: delay, loss, jitter, reorder, fragmentation.
func RegisterTestSimModule(jsCtx map[string]interface{}) {
	jsCtx["Sim"] = map[string]interface{}{
		// Delay adds a fixed delay in milliseconds.
		"Delay": func(ms int64) {
			time.Sleep(time.Duration(ms) * time.Millisecond)
		},

		// RandomDelay adds a random delay between min and max milliseconds.
		"RandomDelay": func(minMs, maxMs int64) {
			if maxMs <= minMs {
				return
			}
			delay := minMs + rand.Int63n(maxMs-minMs)
			time.Sleep(time.Duration(delay) * time.Millisecond)
		},

		// Jitter adds a delay with normal distribution around mean.
		"Jitter": func(meanMs, stddevMs int64) {
			jitter := float64(meanMs) + rand.NormFloat64()*float64(stddevMs)
			if jitter < 0 {
				jitter = 0
			}
			time.Sleep(time.Duration(jitter) * time.Millisecond)
		},

		// ShouldDrop returns true with given probability (0.0 - 1.0) to simulate packet loss.
		"ShouldDrop": func(probability float64) bool {
			return rand.Float64() < probability
		},

		// ShouldCorrupt returns true with given probability for data corruption simulation.
		"ShouldCorrupt": func(probability float64) bool {
			return rand.Float64() < probability
		},

		// CorruptBytes randomly corrupts n bytes in the data.
		"CorruptBytes": func(data []byte, n int) []byte {
			result := make([]byte, len(data))
			copy(result, data)
			for i := 0; i < n && i < len(result); i++ {
				pos := rand.Intn(len(result))
				result[pos] = byte(rand.Intn(256))
			}
			return result
		},

		// Fragment splits data into chunks of given MTU size.
		"Fragment": func(data []byte, mtu int) [][]byte {
			if mtu <= 0 {
				mtu = 1500
			}
			var fragments [][]byte
			for i := 0; i < len(data); i += mtu {
				end := i + mtu
				if end > len(data) {
					end = len(data)
				}
				frag := make([]byte, end-i)
				copy(frag, data[i:end])
				fragments = append(fragments, frag)
			}
			return fragments
		},

		// Reorder shuffles an array of packets (simulates packet reordering).
		"Reorder": func(packets []interface{}) []interface{} {
			result := make([]interface{}, len(packets))
			copy(result, packets)
			rand.Shuffle(len(result), func(i, j int) {
				result[i], result[j] = result[j], result[i]
			})
			return result
		},

		// Duplicate duplicates data with given probability (returns original + duplicate or just original).
		"ShouldDuplicate": func(probability float64) bool {
			return rand.Float64() < probability
		},

		// Throttle sleeps to simulate bandwidth limit.
		// bps: bytes per second, dataSize: size of current packet.
		"Throttle": func(bps int64, dataSize int64) {
			if bps <= 0 {
				return
			}
			sleepMs := (dataSize * 1000) / bps
			if sleepMs > 0 {
				time.Sleep(time.Duration(sleepMs) * time.Millisecond)
			}
		},
	}
}
