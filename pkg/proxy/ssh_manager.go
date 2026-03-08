package proxy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	"golang.org/x/crypto/ssh"
)

var (
	sshManager *SSHManager
	sshOnce    sync.Once
)

type SSHManager struct {
	mu      sync.RWMutex
	clients map[string]*sshClientEntry
}

type sshClientEntry struct {
	client   *ssh.Client
	lastUsed time.Time
}

func GetSSHManager() *SSHManager {
	sshOnce.Do(func() {
		sshManager = &SSHManager{
			clients: make(map[string]*sshClientEntry),
		}
		go sshManager.cleanup()
	})
	return sshManager
}

func (m *SSHManager) cleanup() {
	ticker := time.NewTicker(15 * time.Minute)
	for range ticker.C {
		m.mu.Lock()
		for key, entry := range m.clients {
			if time.Since(entry.lastUsed) > 30*time.Minute {
				logger.Printf("[SSH] 🧹 Closing idle client: %s\n", key)
				entry.client.Close()
				delete(m.clients, key)
			}
		}
		m.mu.Unlock()
	}
}

func (m *SSHManager) GetOrCreateClient(ctx context.Context, cfg *engine.SSHConfig) (*ssh.Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("ssh config is nil")
	}

	key := fmt.Sprintf("%s:%d@%s", cfg.User, cfg.Port, cfg.Host)
	if cfg.Port == 0 {
		key = fmt.Sprintf("%s:22@%s", cfg.User, cfg.Host)
	}

	m.mu.RLock()
	entry, ok := m.clients[key]
	m.mu.RUnlock()

	if ok {
		// Check if client is still alive
		_, _, err := entry.client.SendRequest("keepalive@netkit", true, nil)
		if err == nil {
			entry.lastUsed = time.Now()
			return entry.client, nil
		}
		logger.Printf("[SSH] 🔄 Client %s disconnected, reconnecting...\n", key)
		entry.client.Close()
		m.mu.Lock()
		delete(m.clients, key)
		m.mu.Unlock()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double check
	if entry, ok = m.clients[key]; ok {
		entry.lastUsed = time.Now()
		return entry.client, nil
	}

	sshAddr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	if cfg.Port == 0 {
		sshAddr = fmt.Sprintf("%s:22", cfg.Host)
	}

	auth := []ssh.AuthMethod{}
	if cfg.Pass != "" {
		auth = append(auth, ssh.Password(cfg.Pass))
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	logger.Printf("[SSH] 🚀 Connecting to SSH server %s\n", sshAddr)
	client, err := ssh.Dial("tcp", sshAddr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("ssh dial error: %w", err)
	}

	m.clients[key] = &sshClientEntry{
		client:   client,
		lastUsed: time.Now(),
	}

	return client, nil
}

func (m *SSHManager) Preload(ctx context.Context, cfg *engine.SSHConfig) error {
	_, err := m.GetOrCreateClient(ctx, cfg)
	return err
}
