package session

import (
	"context"
	"sync"
	"time"
)

// Session represents a stateful connection (TCP stream or UDP pseudo-session)
type Session struct {
	ID        string
	Type      string // "TCP", "TLS"
	Source    string
	Dest      string
	StartTime time.Time
	LastSeen  time.Time
	Metadata  map[string]interface{}
	Data      sync.Map    // For custom script data
	Tunnel    interface{} // Stores engine.TunnelConfig
}

// Manager handles the lifecycle of sessions
type Manager interface {
	Get(id string) (*Session, bool)
	Create(id string, sessionType string, src, dst string) *Session
	Remove(id string)
	List() []*Session
	StartCleanup(ctx context.Context, ttl time.Duration)
}

func NewManager() Manager {
	return &manager{
		sessions: make(map[string]*Session),
	}
}

type manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func (m *manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

func (m *manager) Create(id string, sessionType string, src, dst string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &Session{
		ID:        id,
		Type:      sessionType,
		Source:    src,
		Dest:      dst,
		StartTime: time.Now(),
		LastSeen:  time.Now(),
		Metadata:  make(map[string]interface{}, 4),
	}
	m.sessions[id] = s
	return s
}

func (m *manager) Remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Aggressively clean session memory before removing
	if s, ok := m.sessions[id]; ok {
		s.Metadata = nil
		s.Tunnel = nil
	}
	delete(m.sessions, id)
}

func (m *manager) List() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		list = append(list, s)
	}
	return list
}

// StartCleanup runs a background goroutine that removes sessions older than ttl.
// This prevents unbounded memory growth from stale sessions.
func (m *manager) StartCleanup(ctx context.Context, ttl time.Duration) {
	go func() {
		interval := ttl / 2
		if interval < 500*time.Millisecond {
			interval = 500 * time.Millisecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.cleanup(ttl)
			}
		}
	}()
}

// cleanup removes sessions that haven't been seen in longer than ttl.
func (m *manager) cleanup(ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for id, s := range m.sessions {
		if now.Sub(s.LastSeen) > ttl {
			// Aggressively clean before deletion
			s.Metadata = nil
			s.Tunnel = nil
			delete(m.sessions, id)
		}
	}
}
