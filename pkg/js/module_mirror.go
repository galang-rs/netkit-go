package js

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
)

// mirrorRecorder records traffic for replay and export.
type mirrorRecorder struct {
	mu       sync.Mutex
	flows    map[string]*recordedFlow
	pcapFile *os.File
}

type recordedFlow struct {
	ID      string
	Packets []recordedPacket
}

type recordedPacket struct {
	Timestamp int64
	Payload   []byte
	Direction string // "send" or "recv"
}

var globalMirror = &mirrorRecorder{
	flows: make(map[string]*recordedFlow),
}

// RegisterMirrorModule injects ctx.Mirror into the JS context.
func RegisterMirrorModule(jsCtx map[string]interface{}, pkt *engine.Packet, eng engine.Engine) {
	mr := globalMirror

	jsCtx["Mirror"] = map[string]interface{}{
		// Tee clones the current packet payload to the engine (passive clone).
		"Tee": func(payload interface{}) {
			if eng == nil {
				return
			}
			data := gojaToBytes(payload)
			if data == nil && pkt != nil {
				data = pkt.Payload
			}
			if data == nil {
				return
			}
			clone := &engine.Packet{
				ID:        uint64(time.Now().UnixNano()),
				Timestamp: time.Now().Unix(),
				Payload:   make([]byte, len(data)),
			}
			if pkt != nil {
				clone.Source = pkt.Source
				clone.SourcePort = pkt.SourcePort
				clone.Dest = pkt.Dest
				clone.DestPort = pkt.DestPort
				clone.Protocol = pkt.Protocol
			}
			copy(clone.Payload, data)
			eng.Ingest(clone)
		},

		// Record stores a packet for later replay.
		"Record": func(flowID string, payload []byte, direction string) {
			mr.mu.Lock()
			defer mr.mu.Unlock()
			flow, ok := mr.flows[flowID]
			if !ok {
				flow = &recordedFlow{ID: flowID}
				mr.flows[flowID] = flow
			}
			pktCopy := make([]byte, len(payload))
			copy(pktCopy, payload)
			flow.Packets = append(flow.Packets, recordedPacket{
				Timestamp: time.Now().UnixMilli(),
				Payload:   pktCopy,
				Direction: direction,
			})
		},

		// GetRecording returns all recorded packets for a flow.
		"GetRecording": func(flowID string) []map[string]interface{} {
			mr.mu.Lock()
			defer mr.mu.Unlock()
			flow, ok := mr.flows[flowID]
			if !ok {
				return nil
			}
			var result []map[string]interface{}
			for _, p := range flow.Packets {
				result = append(result, map[string]interface{}{
					"timestamp": p.Timestamp,
					"payload":   p.Payload,
					"direction": p.Direction,
					"size":      len(p.Payload),
				})
			}
			return result
		},

		// Replay replays recorded packets with original timing.
		"Replay": func(flowID string) {
			if eng == nil {
				return
			}
			mr.mu.Lock()
			flow, ok := mr.flows[flowID]
			mr.mu.Unlock()
			if !ok || len(flow.Packets) == 0 {
				return
			}

			baseTime := flow.Packets[0].Timestamp
			for _, p := range flow.Packets {
				delay := p.Timestamp - baseTime
				if delay > 0 {
					time.Sleep(time.Duration(delay) * time.Millisecond)
				}
				replayPkt := &engine.Packet{
					ID:        uint64(time.Now().UnixNano()),
					Timestamp: time.Now().Unix(),
					Payload:   p.Payload,
				}
				eng.Ingest(replayPkt)
				baseTime = p.Timestamp
			}
		},

		// ClearRecording removes a flow recording.
		"ClearRecording": func(flowID string) {
			mr.mu.Lock()
			delete(mr.flows, flowID)
			mr.mu.Unlock()
		},

		// ClearAll removes all recordings.
		"ClearAll": func() {
			mr.mu.Lock()
			mr.flows = make(map[string]*recordedFlow)
			mr.mu.Unlock()
		},

		// ListRecordings returns all flow IDs with packet counts.
		"ListRecordings": func() []map[string]interface{} {
			mr.mu.Lock()
			defer mr.mu.Unlock()
			var result []map[string]interface{}
			for id, flow := range mr.flows {
				result = append(result, map[string]interface{}{
					"id":          id,
					"packetCount": len(flow.Packets),
				})
			}
			return result
		},

		// SavePCAP exports recorded flow to a PCAP-like raw file.
		"SaveRaw": func(flowID, path string) error {
			mr.mu.Lock()
			flow, ok := mr.flows[flowID]
			mr.mu.Unlock()
			if !ok {
				return fmt.Errorf("flow %s not found", flowID)
			}

			fsMutex.Lock()
			defer fsMutex.Unlock()

			f, err := os.Create(path)
			if err != nil {
				return err
			}
			defer f.Close()

			for _, p := range flow.Packets {
				// Write timestamp (8 bytes) + length (4 bytes) + payload
				ts := make([]byte, 8)
				for i := 0; i < 8; i++ {
					ts[i] = byte(p.Timestamp >> (i * 8))
				}
				f.Write(ts)
				lenBytes := make([]byte, 4)
				l := len(p.Payload)
				lenBytes[0] = byte(l)
				lenBytes[1] = byte(l >> 8)
				lenBytes[2] = byte(l >> 16)
				lenBytes[3] = byte(l >> 24)
				f.Write(lenBytes)
				f.Write(p.Payload)
			}
			return nil
		},
	}
}
