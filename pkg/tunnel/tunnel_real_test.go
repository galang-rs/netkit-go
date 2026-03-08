package tunnel_test

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bacot120211/netkit-go/pkg/cgnat"
	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/tunnel"
)

func TestTunnelReal_ProductFlow(t *testing.T) {
	// 1. CGNAT Detection (Real-world network check)
	detector := cgnat.NewDetector()
	res, err := detector.QuickDetect()
	if err != nil {
		t.Logf("CGNAT Detection failed (offline?): %v", err)
	} else {
		t.Logf("Detected NAT: %s, Public IP: %s", res.NATType, res.PublicIP)
	}

	// 2. Setup Tunnel Server (Localhost)
	e := engine.New()
	auth := func(u, p string) bool {
		return u == "testuser" && p == "testpass"
	}
	// Use port 0 for dynamic allocation to avoid "port in use" conflicts
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen for tunnel server: %v", err)
	}
	serverAddr := srvLn.Addr().String()
	srvLn.Close() // Close it so srv.Start() can use it (there's a tiny race but usually fine in tests)

	srv := tunnel.NewNKTunnelServer(serverAddr, auth, e, nil, "21000-21010")

	errChan := make(chan error, 1)
	go func() {
		if err := srv.Start(); err != nil {
			errChan <- err
		}
	}()

	// Wait for server to bind
	time.Sleep(500 * time.Millisecond)
	select {
	case err := <-errChan:
		t.Fatalf("Tunnel Server failed to start: %v", err)
	default:
	}

	// 3. Setup Local Target (The service we want to expose)
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start local target: %v", err)
	}
	defer targetLn.Close()
	targetAddr := targetLn.Addr().String()

	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.WriteString(c, "Hello from Tunnel Product!")
			}(conn)
		}
	}()

	// 4. Setup Tunnel Client
	cli := tunnel.NewNKTunnelClient(serverAddr, "testuser", "testpass", targetAddr, "21000", "tcp")
	if err := cli.Start(); err != nil {
		t.Fatalf("Failed to start tunnel client: %v", err)
	}
	defer cli.Stop()

	// Wait for tunnel negotiation to finish
	time.Sleep(1000 * time.Millisecond)

	start, count := cli.GetAssignedPorts()
	if count == 0 {
		t.Fatalf("No ports assigned by server (negotiation failed?)")
	}
	t.Logf("Tunnel active on port: %d (Range: %d)", start, count)

	// 5. Verify: Connect to Server's assigned port
	publicAddr := fmt.Sprintf("127.0.0.1:%d", start)

	// Retry connection a few times if needed
	var conn net.Conn
	var dialErr error
	for i := 0; i < 5; i++ {
		conn, dialErr = net.DialTimeout("tcp", publicAddr, 2*time.Second)
		if dialErr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if dialErr != nil {
		t.Fatalf("Failed to connect to tunnel endpoint %s after retries: %v", publicAddr, dialErr)
	}
	defer conn.Close()

	respBuf := make([]byte, 64)
	n, err := conn.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read response through tunnel: %v", err)
	}

	expected := "Hello from Tunnel Product!"
	if string(respBuf[:n]) != expected {
		t.Errorf("Data corruption through tunnel! Expected %q, got %q", expected, string(respBuf[:n]))
	} else {
		t.Logf("Tunnel verified! Successfully relayed: %s", string(respBuf[:n]))
	}
}
