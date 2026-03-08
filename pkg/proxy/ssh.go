package proxy

import (
	"context"
	"fmt"
	"net"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
)

// dialUpstreamSSH connects to an upstream SSH server and creates a tunnel for the target address.
func dialUpstreamSSH(ctx context.Context, cfg *engine.SSHConfig, targetAddr string) (net.Conn, error) {
	client, err := GetSSHManager().GetOrCreateClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	logger.Printf("[SSH] 🚀 Creating tunnel to %s via shared client\n", targetAddr)

	// Create a tunnel to the target address through the SSH connection
	conn, err := client.Dial("tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("ssh tunnel dial error: %w", err)
	}

	return conn, nil
}
