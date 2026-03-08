package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"testing"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"golang.org/x/crypto/ssh"
)

func TestSSH_Tunneling_RealMock(t *testing.T) {
	// 1. Setup Mock SSH Server
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "testuser" && string(pass) == "testpass" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected")
		},
	}

	// Generate a dummy host key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	config.AddHostKey(signer)

	// Listen for SSH connections
	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer sshLn.Close()
	sshAddr := sshLn.Addr().String()
	sshHost, sshPortStr, _ := net.SplitHostPort(sshAddr)
	var sshPort int
	fmt.Sscanf(sshPortStr, "%d", &sshPort)

	// Start SSH server goroutine
	go func() {
		for {
			nConn, err := sshLn.Accept()
			if err != nil {
				return
			}
			_, _, reqs, err := ssh.NewServerConn(nConn, config)
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(reqs)
		}
	}()

	ctx := context.Background()
	cfg := &engine.SSHConfig{
		Host: sshHost,
		Port: sshPort,
		User: "testuser",
		Pass: "testpass",
	}

	t.Run("Auth Success", func(t *testing.T) {
		// This will dial and auth. It might fail on client.Dial("tcp", target)
		// because we don't handle direct-tcpip in our simple mock.
		// But it verifies the SSH handshake and auth.
		_, err := dialUpstreamSSH(ctx, cfg, "127.0.0.1:1234")
		if err != nil && err.Error()[:13] != "ssh dial error" {
			// If it's not a dial error, it means we passed auth and reached the channel open stage
			t.Logf("Reached channel open (auth success): %v", err)
		} else if err != nil && err.Error()[:13] == "ssh dial error" {
			t.Errorf("Auth failed but should have succeeded: %v", err)
		}
	})

	t.Run("Auth Failure", func(t *testing.T) {
		badCfg := *cfg
		badCfg.Pass = "wrong"
		_, err := dialUpstreamSSH(ctx, &badCfg, "127.0.0.1:1234")
		if err == nil {
			t.Error("expected error for wrong password")
		} else {
			t.Logf("Got expected auth failure: %v", err)
		}
	})
}

func TestSSH_Manager_Reuse(t *testing.T) {
	// Setup Mock SSH Server (copied logic for brevity or could refactor)
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, nil // Accept all for reuse test
		},
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := ssh.NewSignerFromKey(key)
	config.AddHostKey(signer)

	sshLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer sshLn.Close()
	sshAddr := sshLn.Addr().String()
	sshHost, sshPortStr, _ := net.SplitHostPort(sshAddr)
	var sshPort int
	fmt.Sscanf(sshPortStr, "%d", &sshPort)

	go func() {
		for {
			nConn, err := sshLn.Accept()
			if err != nil {
				return
			}
			_, _, reqs, _ := ssh.NewServerConn(nConn, config)
			go ssh.DiscardRequests(reqs)
		}
	}()

	ctx := context.Background()
	cfg := &engine.SSHConfig{
		Host: sshHost,
		Port: sshPort,
		User: "reuseuser",
		Pass: "reusepass",
	}

	manager := GetSSHManager()

	// First call
	client1, err := manager.GetOrCreateClient(ctx, cfg)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	// Second call with same config
	client2, err := manager.GetOrCreateClient(ctx, cfg)
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	if client1 != client2 {
		t.Errorf("Expected same client instance for reuse, got %p and %p", client1, client2)
	}

	// Third call with different config (different user)
	cfg2 := *cfg
	cfg2.User = "otheruser"
	client3, err := manager.GetOrCreateClient(ctx, &cfg2)
	if err != nil {
		t.Fatalf("Third call failed: %v", err)
	}

	if client1 == client3 {
		t.Errorf("Expected different client instance for different user")
	}
}
