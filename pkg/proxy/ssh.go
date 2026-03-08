package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	"golang.org/x/crypto/ssh"
)

// dialUpstreamSSH connects to an upstream SSH server and creates a tunnel for the target address.
func dialUpstreamSSH(ctx context.Context, cfg *engine.SSHConfig, targetAddr string) (net.Conn, error) {
	if cfg == nil {
		return nil, fmt.Errorf("ssh config is nil")
	}

	sshAddr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	if cfg.Port == 0 {
		sshAddr = fmt.Sprintf("%s:22", cfg.Host)
	}

	auth := []ssh.AuthMethod{}
	if cfg.Pass != "" {
		auth = append(auth, ssh.Password(cfg.Pass))
	}
	// TODO: Support PrivateKey if needed

	sshConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For now, maybe add option later
		Timeout:         10 * time.Second,
	}

	logger.Printf("[SSH] 🚀 Dialing SSH server %s for tunnel to %s\n", sshAddr, targetAddr)

	// Connect to the SSH server
	client, err := ssh.Dial("tcp", sshAddr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("ssh dial error: %w", err)
	}

	// Create a tunnel to the target address through the SSH connection
	conn, err := client.Dial("tcp", targetAddr)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("ssh tunnel dial error: %w", err)
	}

	// Wrap connection to ensure SSH client is closed when connection is closed
	return &sshConn{
		Conn:   conn,
		client: client,
	}, nil
}

type sshConn struct {
	net.Conn
	client *ssh.Client
}

func (c *sshConn) Close() error {
	err := c.Conn.Close()
	if c.client != nil {
		c.client.Close()
	}
	return err
}
