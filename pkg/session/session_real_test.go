package session

import (
	"context"
	"testing"
	"time"
)

func TestSessionReal_Lifecycle(t *testing.T) {
	mgr := NewManager()
	id := "tcp-127.0.0.1:12345-1.1.1.1:80"

	// 1. Create session (Real product behavior)
	s := mgr.Create(id, "TCP", "127.0.0.1:12345", "1.1.1.1:80")
	if s.ID != id {
		t.Errorf("Expected session ID %s, got %s", id, s.ID)
	}

	// 2. Metadata storage (Simulating JS usage)
	s.Metadata["Service"] = "HTTP"
	s.Data.Store("IsEvil", true)

	// 3. Retrieval
	s2, ok := mgr.Get(id)
	if !ok || s2.Metadata["Service"] != "HTTP" {
		t.Errorf("Session retrieval or metadata fail")
	}

	// 4. Cleanup Test (Production memory management)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Manually set LastSeen back to trigger cleanup
	s.LastSeen = time.Now().Add(-10 * time.Minute)

	// Start cleanup with 1s TTL
	mgr.StartCleanup(ctx, 1*time.Second)

	// Wait for cleanup ticker (interval is TTL/2 = 500ms)
	time.Sleep(1500 * time.Millisecond)

	if _, ok := mgr.Get(id); ok {
		t.Errorf("Session should have been cleaned up by TTL manager")
	} else {
		t.Logf("Session cleanup verified! Memory reclaimed.")
	}
}
