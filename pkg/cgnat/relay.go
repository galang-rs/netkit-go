package cgnat

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// RelayConfig configures the relay connection.
type RelayConfig struct {
	// ServerAddr is the relay server address.
	ServerAddr string
	// AuthToken authenticates this client to the relay.
	AuthToken string
	// PeerID of the target peer on the relay.
	PeerID string
	// EncryptionKey for end-to-end encryption (32 bytes for XChaCha20-Poly1305).
	EncryptionKey []byte
	// Timeout for connecting to relay.
	Timeout time.Duration
}

// RelayConn wraps a relayed connection with encryption.
type RelayConn struct {
	conn   net.Conn
	key    []byte
	peerID string
	mu     sync.Mutex
}

// NewRelayConnection connects to a relay server and establishes a channel to the peer.
func NewRelayConnection(ctx context.Context, cfg *RelayConfig) (*RelayConn, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	dialer := net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("connect relay %s: %w", cfg.ServerAddr, err)
	}

	// Handshake: send AUTH + PEER_ID
	handshake := fmt.Sprintf("NKRELAY\x00AUTH:%s\x00PEER:%s\x00", cfg.AuthToken, cfg.PeerID)
	if _, err := conn.Write([]byte(handshake)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("relay handshake: %w", err)
	}

	// Read server ACK
	ack := make([]byte, 16)
	conn.SetReadDeadline(time.Now().Add(cfg.Timeout))
	n, err := conn.Read(ack)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("relay ACK: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	if string(ack[:n]) != "NKOK\x00" {
		conn.Close()
		return nil, fmt.Errorf("relay rejected: %s", string(ack[:n]))
	}

	return &RelayConn{
		conn:   conn,
		key:    cfg.EncryptionKey,
		peerID: cfg.PeerID,
	}, nil
}

// Send sends encrypted data through the relay.
func (rc *RelayConn) Send(data []byte) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	var payload []byte
	if rc.key != nil && len(rc.key) == chacha20poly1305.KeySize {
		encrypted, err := encryptChaCha(rc.key, data)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
		payload = encrypted
	} else {
		payload = data
	}

	// Frame: [4 bytes length][payload]
	frame := make([]byte, 4+len(payload))
	frame[0] = byte(len(payload) >> 24)
	frame[1] = byte(len(payload) >> 16)
	frame[2] = byte(len(payload) >> 8)
	frame[3] = byte(len(payload))
	copy(frame[4:], payload)

	_, err := rc.conn.Write(frame)
	return err
}

// Receive reads and decrypts data from the relay.
func (rc *RelayConn) Receive() ([]byte, error) {
	// Read frame length
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(rc.conn, lenBuf); err != nil {
		return nil, fmt.Errorf("read frame length: %w", err)
	}
	payloadLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])

	if payloadLen > 65536 {
		return nil, fmt.Errorf("relay frame too large: %d", payloadLen)
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(rc.conn, payload); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}

	if rc.key != nil && len(rc.key) == chacha20poly1305.KeySize {
		decrypted, err := decryptChaCha(rc.key, payload)
		if err != nil {
			return nil, fmt.Errorf("decrypt: %w", err)
		}
		return decrypted, nil
	}

	return payload, nil
}

// Close closes the relay connection.
func (rc *RelayConn) Close() error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.conn != nil {
		err := rc.conn.Close()
		rc.conn = nil
		rc.key = nil
		return err
	}
	return nil
}

// encryptChaCha encrypts data with XChaCha20-Poly1305.
func encryptChaCha(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptChaCha decrypts data with XChaCha20-Poly1305.
func decryptChaCha(key, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:nonceSize]
	data := ciphertext[nonceSize:]
	return aead.Open(nil, nonce, data, nil)
}
