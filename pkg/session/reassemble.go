package session

import (
	"sort"
	"sync"
)

// Segment represents a TCP segment for reassembly
type Segment struct {
	Seq     uint32
	Payload []byte
}

// StreamReassembler handles TCP stream reconstruction
type StreamReassembler struct {
	segments []Segment
	mu       sync.Mutex
	nextSeq  uint32
	started  bool
}

func NewStreamReassembler() *StreamReassembler {
	return &StreamReassembler{
		segments: make([]Segment, 0),
	}
}

// Add appends a segment and returns reassembled data if possible
func (r *StreamReassembler) Add(seq uint32, payload []byte) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.started {
		r.nextSeq = seq
		r.started = true
	}

	r.segments = append(r.segments, Segment{Seq: seq, Payload: payload})
	sort.Slice(r.segments, func(i, j int) bool {
		return r.segments[i].Seq < r.segments[j].Seq
	})

	var result []byte
	for i := 0; i < len(r.segments); {
		s := r.segments[i]
		if s.Seq == r.nextSeq {
			result = append(result, s.Payload...)
			r.nextSeq += uint32(len(s.Payload))
			r.segments = append(r.segments[:i], r.segments[i+1:]...)
		} else if s.Seq < r.nextSeq {
			// Overlapping or duplicate segment
			r.segments = append(r.segments[:i], r.segments[i+1:]...)
		} else {
			i++
		}
	}

	return result
}
