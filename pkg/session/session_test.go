package session

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestManager_Create_Get(t *testing.T) {
	m := NewManager()
	s := m.Create("session-1", "TCP", "10.0.0.1", "10.0.0.2")

	if s.ID != "session-1" {
		t.Errorf("Expected ID 'session-1', got '%s'", s.ID)
	}
	if s.Type != "TCP" {
		t.Errorf("Expected Type 'TCP', got '%s'", s.Type)
	}

	got, ok := m.Get("session-1")
	if !ok {
		t.Fatal("Session should exist after Create")
	}
	if got != s {
		t.Error("Get should return the same session object")
	}
}

func TestManager_Get_NotFound(t *testing.T) {
	m := NewManager()
	_, ok := m.Get("nonexistent")
	if ok {
		t.Error("Get should return false for nonexistent session")
	}
}

func TestManager_Remove(t *testing.T) {
	m := NewManager()
	m.Create("session-1", "TCP", "10.0.0.1", "10.0.0.2")

	m.Remove("session-1")

	_, ok := m.Get("session-1")
	if ok {
		t.Error("Session should not exist after Remove")
	}
}

func TestManager_Remove_ClearsMemory(t *testing.T) {
	m := NewManager()
	s := m.Create("session-1", "TCP", "10.0.0.1", "10.0.0.2")
	s.Metadata["key"] = "value"
	s.Tunnel = "some-config"

	m.Remove("session-1")

	if s.Metadata != nil {
		t.Error("Metadata should be nil after remove (aggressive cleanup)")
	}
	if s.Tunnel != nil {
		t.Error("Tunnel should be nil after remove (aggressive cleanup)")
	}
}

func TestManager_List(t *testing.T) {
	m := NewManager()
	m.Create("s1", "TCP", "a", "b")
	m.Create("s2", "UDP", "c", "d")

	list := m.List()
	if len(list) != 2 {
		t.Errorf("Expected 2 sessions, got %d", len(list))
	}
}

func TestManager_List_Empty(t *testing.T) {
	m := NewManager()
	list := m.List()
	if len(list) != 0 {
		t.Errorf("Expected 0 sessions, got %d", len(list))
	}
}

func TestManager_Cleanup_RemovesStale(t *testing.T) {
	m := NewManager()
	s := m.Create("old", "TCP", "a", "b")
	s.LastSeen = time.Now().Add(-5 * time.Second) // Force it to be old

	m.Create("new", "TCP", "c", "d")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.StartCleanup(ctx, 2*time.Second) // TTL = 2s, cleanup interval = 1s

	// Wait for cleanup to run (interval is ttl/2 = 1s, min 10s)
	time.Sleep(1500 * time.Millisecond)

	_, oldExists := m.Get("old")
	_, newExists := m.Get("new")

	if oldExists {
		t.Error("Old session should be cleaned up")
	}
	if !newExists {
		t.Error("New session should still exist")
	}
}

func TestManager_Cleanup_StopsOnCancel(t *testing.T) {
	m := NewManager()
	ctx, cancel := context.WithCancel(context.Background())
	m.StartCleanup(ctx, 1*time.Second)
	cancel()
	// Should not hang or panic
	time.Sleep(100 * time.Millisecond)
}

// --- Concurrent Access (race detector) ---

func TestManager_Concurrent(t *testing.T) {
	m := NewManager()
	const goroutines = 50

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			sid := "session-" + time.Now().Format("15:04:05.000000") + "-" + string(rune(id))
			m.Create(sid, "TCP", "a", "b")
			m.Get(sid)
			m.List()
			m.Remove(sid)
		}(i)
	}
	wg.Wait()
}

// --- Benchmarks ---

func BenchmarkManager_Create(b *testing.B) {
	m := NewManager()
	for i := 0; i < b.N; i++ {
		m.Create("s", "TCP", "a", "b")
	}
}

func BenchmarkManager_Get(b *testing.B) {
	m := NewManager()
	m.Create("s", "TCP", "a", "b")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Get("s")
	}
}

func BenchmarkManager_List(b *testing.B) {
	m := NewManager()
	for i := 0; i < 100; i++ {
		m.Create("s-"+string(rune(i)), "TCP", "a", "b")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.List()
	}
}
