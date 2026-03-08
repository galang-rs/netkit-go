package proxy

import (
	"sync"
	"testing"
)

func TestMirror_Clone_NilConn(t *testing.T) {
	m := &Mirror{addr: "127.0.0.1:99999", conn: nil}
	// Should not panic — will attempt reconnect but fail (invalid port)
	m.Clone([]byte("test"))
}

func TestMirror_Clone_Concurrent_Mutex(t *testing.T) {
	// Verify that Clone doesn't race with itself
	m := &Mirror{addr: "127.0.0.1:99999"}
	// conn is nil so clone will try to reconnect and fail, but shouldn't race

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Clone([]byte("x"))
		}()
	}
	wg.Wait()
}

func TestMirror_Close_NilConn(t *testing.T) {
	m := &Mirror{addr: "test:1234"}
	err := m.Close()
	if err != nil {
		t.Errorf("Close on nil conn should not error: %v", err)
	}
}

func TestMirror_Close_SetsNil(t *testing.T) {
	m := &Mirror{addr: "test:1234"}
	// Even with a nil conn, Close should work
	_ = m.Close()
	if m.conn != nil {
		t.Error("conn should be nil after Close")
	}
}
