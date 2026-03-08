package proxy

import (
	"net"
	"sync"

	"github.com/bacot120211/netkit-go/pkg/logger"
)

// Mirror represents a passive traffic clone/mirror
type Mirror struct {
	addr string
	conn net.Conn
	mu   sync.Mutex // protects concurrent Clone calls
}

func NewMirror(addr string) (*Mirror, error) {
	conn, err := net.Dial("tcp", addr) // Mirroring via TCP for logging/IDS
	if err != nil {
		return nil, err
	}

	return &Mirror{
		addr: addr,
		conn: conn,
	}, nil
}

// Clone sends a copy of the payload to the mirror target.
// Thread-safe: protected by mutex. Auto-reconnects on failure.
func (m *Mirror) Clone(payload []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn == nil {
		// Try to reconnect
		conn, err := net.Dial("tcp", m.addr)
		if err != nil {
			return // Silently fail, will retry next time
		}
		m.conn = conn
	}

	_, err := m.conn.Write(payload)
	if err != nil {
		logger.Printf("[Mirror] Connection lost, will reconnect: %v\n", err)
		m.conn.Close()
		m.conn = nil // Release for GC, will reconnect on next Clone
	}
}

func (m *Mirror) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conn != nil {
		err := m.conn.Close()
		m.conn = nil // Release for GC
		return err
	}
	return nil
}
