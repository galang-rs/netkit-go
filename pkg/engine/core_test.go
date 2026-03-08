package engine

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockInterceptor is a test helper that records calls
type mockInterceptor struct {
	name      string
	onPacket  func(ctx *PacketContext) error
	onConnect func(info *ConnInfo) *TunnelConfig
}

func (m *mockInterceptor) Name() string { return m.name }
func (m *mockInterceptor) OnConnect(info *ConnInfo) *TunnelConfig {
	if m.onConnect != nil {
		return m.onConnect(info)
	}
	return nil
}
func (m *mockInterceptor) OnPacket(ctx *PacketContext) error {
	if m.onPacket != nil {
		return m.onPacket(ctx)
	}
	return nil
}

// mockPacketWriter records written packets
type mockPacketWriter struct {
	mu      sync.Mutex
	packets [][]byte
}

func (w *mockPacketWriter) WritePacket(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	w.packets = append(w.packets, cp)
	return nil
}
func (w *mockPacketWriter) Close() error { return nil }

func (w *mockPacketWriter) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.packets)
}

// --- NextPacketID ---

func TestNextPacketID_Unique(t *testing.T) {
	ids := make(map[uint64]bool)
	for i := 0; i < 10000; i++ {
		id := NextPacketID()
		if ids[id] {
			t.Fatalf("Duplicate packet ID: %d", id)
		}
		ids[id] = true
	}
}

func TestNextPacketID_Concurrent(t *testing.T) {
	const goroutines = 100
	const idsPerGoroutine = 1000

	allIDs := make(chan uint64, goroutines*idsPerGoroutine)
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < idsPerGoroutine; j++ {
				allIDs <- NextPacketID()
			}
		}()
	}

	wg.Wait()
	close(allIDs)

	seen := make(map[uint64]bool)
	for id := range allIDs {
		if seen[id] {
			t.Fatalf("Duplicate ID under concurrency: %d", id)
		}
		seen[id] = true
	}
	if len(seen) != goroutines*idsPerGoroutine {
		t.Fatalf("Expected %d unique IDs, got %d", goroutines*idsPerGoroutine, len(seen))
	}
}

// --- ReleasePacket ---

func TestReleasePacket_ClearsAllFields(t *testing.T) {
	p := &Packet{
		ID:          42,
		Payload:     []byte("hello"),
		Metadata:    map[string]interface{}{"key": "val"},
		Conn:        &ConnInfo{Type: "test"},
		Source:      "1.1.1.1",
		Dest:        "2.2.2.2",
		Protocol:    "TCP",
		ProcessName: "test.exe",
	}

	ReleasePacket(p)

	if p.Payload != nil {
		t.Error("Payload should be nil after release")
	}
	if p.Metadata != nil {
		t.Error("Metadata should be nil after release")
	}
	if p.Conn != nil {
		t.Error("Conn should be nil after release")
	}
	if p.Source != "" || p.Dest != "" || p.Protocol != "" || p.ProcessName != "" {
		t.Error("String fields should be empty after release")
	}
}

func TestReleasePacket_NilSafe(t *testing.T) {
	// Should not panic
	ReleasePacket(nil)
}

// --- Engine Process ---

func TestEngine_Process_NoInterceptors(t *testing.T) {
	e := New()
	p := &Packet{
		ID:       1,
		Source:   "10.0.0.1",
		Dest:     "10.0.0.2",
		Protocol: "TCP",
		Payload:  []byte("test"),
	}

	action := e.Process(p, nil)
	if action != ActionContinue {
		t.Errorf("Expected ActionContinue, got %d", action)
	}
}

func TestEngine_Process_InterceptorDrop(t *testing.T) {
	e := New()
	e.RegisterInterceptor(&mockInterceptor{
		name: "dropper",
		onPacket: func(ctx *PacketContext) error {
			ctx.Action = ActionDrop
			return nil
		},
	})

	p := &Packet{
		ID: 2, Source: "1.1.1.1", Dest: "2.2.2.2", Protocol: "TCP",
		Payload: []byte("drop me"),
	}
	action := e.Process(p, nil)
	if action != ActionDrop {
		t.Errorf("Expected ActionDrop, got %d", action)
	}
}

func TestEngine_Process_InterceptorModify(t *testing.T) {
	e := New()
	e.RegisterInterceptor(&mockInterceptor{
		name: "modifier",
		onPacket: func(ctx *PacketContext) error {
			ctx.Packet.Payload = []byte("modified")
			return nil
		},
	})

	p := &Packet{
		ID: 3, Source: "1.1.1.1", Dest: "2.2.2.2", Protocol: "TCP",
		Payload: []byte("original"),
	}
	action := e.Process(p, nil)
	if action != ActionContinue {
		t.Errorf("Expected ActionContinue, got %d", action)
	}
	if string(p.Payload) != "modified" {
		t.Errorf("Payload should be modified, got %s", string(p.Payload))
	}
}

func TestEngine_Process_InterceptorError(t *testing.T) {
	e := New()
	var secondCalled bool
	e.RegisterInterceptor(&mockInterceptor{
		name: "error-interceptor",
		onPacket: func(ctx *PacketContext) error {
			return fmt.Errorf("interceptor error")
		},
	})
	e.RegisterInterceptor(&mockInterceptor{
		name: "second",
		onPacket: func(ctx *PacketContext) error {
			secondCalled = true
			return nil
		},
	})

	p := &Packet{
		ID: 4, Source: "1.1.1.1", Dest: "2.2.2.2", Protocol: "TCP",
		Payload: []byte("test"),
	}
	e.Process(p, nil)

	// Second interceptor should NOT be called because first returned error
	if secondCalled {
		t.Error("Second interceptor should not be called after first errored")
	}
}

func TestEngine_Process_PcapWriter(t *testing.T) {
	e := New()
	writer := &mockPacketWriter{}
	e.SetPcapWriter(writer)

	p := &Packet{
		ID: 5, Source: "1.1.1.1", Dest: "2.2.2.2", Protocol: "TCP",
		Payload: []byte("capture-me"),
	}
	e.Process(p, nil)

	if writer.Count() != 1 {
		t.Errorf("Expected 1 packet written, got %d", writer.Count())
	}
}

func TestEngine_Process_WithFilter_Match(t *testing.T) {
	e := New()
	e.SetFilter(NewFilter("proto tcp"))

	p := &Packet{
		ID: 6, Source: "1.1.1.1", Dest: "2.2.2.2", Protocol: "TCP",
		Payload: []byte("test"),
	}
	action := e.Process(p, nil)
	if action != ActionContinue {
		t.Errorf("Expected ActionContinue for matching filter, got %d", action)
	}
}

func TestEngine_Process_WithFilter_NoMatch(t *testing.T) {
	e := New()
	e.SetFilter(NewFilter("proto udp"))

	p := &Packet{
		ID: 7, Source: "1.1.1.1", Dest: "2.2.2.2", Protocol: "TCP",
		Payload: []byte("test"),
	}
	action := e.Process(p, nil)
	if action != ActionContinue {
		t.Errorf("Filtered packets should return ActionContinue, got %d", action)
	}
}

// --- Engine Ingest ---

func TestEngine_Ingest_NilPacket(t *testing.T) {
	e := New()
	// Should not panic
	e.Ingest(nil)
}

func TestEngine_Ingest_AfterClose(t *testing.T) {
	eng := New().(*coreEngine)
	close(eng.closeChan)
	// Fill the packet channel so select can only hit closeChan or default
	// Both paths call ReleasePacket.
	for i := 0; i < cap(eng.packetChan); i++ {
		eng.packetChan <- &Packet{}
	}
	// Should not panic, packet should be released
	p := &Packet{ID: 1, Payload: []byte("test")}
	eng.Ingest(p)
	if p.Payload != nil {
		t.Error("Packet should be released after ingest to closed engine")
	}
}

// --- Engine Start/Stop ---

func TestEngine_StartStop(t *testing.T) {
	e := New()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- e.Start(ctx)
	}()

	// Give workers time to start
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start should return nil on clean shutdown, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Engine did not shut down within 5 seconds")
	}
}

func TestEngine_Stop_PropagatiesErrors(t *testing.T) {
	e := New()
	e.RegisterInterceptor(&mockCloserInterceptor{
		name: "bad-closer",
		err:  fmt.Errorf("close failed"),
	})

	err := e.Stop()
	if err == nil {
		t.Error("Stop should return error when interceptor close fails")
	}
}

type mockCloserInterceptor struct {
	name string
	err  error
}

func (m *mockCloserInterceptor) Name() string                           { return m.name }
func (m *mockCloserInterceptor) OnConnect(info *ConnInfo) *TunnelConfig { return nil }
func (m *mockCloserInterceptor) OnPacket(ctx *PacketContext) error      { return nil }
func (m *mockCloserInterceptor) Close() error                           { return m.err }

// --- Concurrent Process (race detector) ---

func TestEngine_Process_Concurrent(t *testing.T) {
	e := New()
	var count atomic.Int64
	e.RegisterInterceptor(&mockInterceptor{
		name: "counter",
		onPacket: func(ctx *PacketContext) error {
			count.Add(1)
			return nil
		},
	})

	const goroutines = 50
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p := &Packet{
				ID:       uint64(id),
				Source:   "10.0.0.1",
				Dest:     "10.0.0.2",
				Protocol: "TCP",
				Payload:  []byte("concurrent"),
			}
			e.Process(p, nil)
		}(i)
	}
	wg.Wait()

	if count.Load() != goroutines {
		t.Errorf("Expected %d interceptor calls, got %d", goroutines, count.Load())
	}
}

// --- RegisterDomain / SetOnDomain ---

func TestEngine_RegisterDomain(t *testing.T) {
	e := New().(*coreEngine)
	var called string
	e.SetOnDomain(func(d string) {
		called = d
	})
	e.RegisterDomain("example.com")
	if called != "example.com" {
		t.Errorf("Expected domain 'example.com', got '%s'", called)
	}
}

func TestEngine_RegisterDomain_NilHandler(t *testing.T) {
	e := New().(*coreEngine)
	// Should not panic when OnDomain is nil
	e.RegisterDomain("example.com")
}

// --- GetIPType ---

func TestGetIPType(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
	}{
		{"127.0.0.1", "localhost"},
		{"::1", "localhost"},
		{"192.168.1.1", "private"},
		{"10.0.0.1", "private"},
		{"172.16.0.1", "private"},
		{"8.8.8.8", "public"},
		{"1.1.1.1", "public"},
		{"invalid", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := GetIPType(tt.ip)
			if result != tt.expected {
				t.Errorf("GetIPType(%s) = %s, want %s", tt.ip, result, tt.expected)
			}
		})
	}
}

// --- Benchmarks ---

func BenchmarkNextPacketID(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			NextPacketID()
		}
	})
}

func BenchmarkReleasePacket(b *testing.B) {
	for i := 0; i < b.N; i++ {
		p := &Packet{
			Payload:  make([]byte, 1024),
			Metadata: map[string]interface{}{"key": "val"},
			Conn:     &ConnInfo{},
		}
		ReleasePacket(p)
	}
}

func BenchmarkProcess_NoInterceptors(b *testing.B) {
	e := New()
	p := &Packet{
		ID: 1, Source: "10.0.0.1", Dest: "10.0.0.2", Protocol: "TCP",
		Payload: []byte("benchmark"),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Process(p, nil)
	}
}

func BenchmarkProcess_OneInterceptor(b *testing.B) {
	e := New()
	e.RegisterInterceptor(&mockInterceptor{
		name:     "noop",
		onPacket: func(ctx *PacketContext) error { return nil },
	})
	p := &Packet{
		ID: 1, Source: "10.0.0.1", Dest: "10.0.0.2", Protocol: "TCP",
		Payload: []byte("benchmark"),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Process(p, nil)
	}
}

func BenchmarkIngest(b *testing.B) {
	e := New()
	ctx, cancel := context.WithCancel(context.Background())
	go e.Start(ctx)
	defer cancel()
	time.Sleep(20 * time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := &Packet{
			ID: uint64(i), Source: "10.0.0.1", Dest: "10.0.0.2", Protocol: "TCP",
			Payload: []byte("bench"),
		}
		e.Ingest(p)
	}
}
