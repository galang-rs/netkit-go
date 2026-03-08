package capture

import (
	"context"
	"fmt"
	"net"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/proxy"
)

type TCPListener struct {
	addr       string
	targetAddr string
	engine     engine.Engine
}

func NewTCPListener(addr, targetAddr string, e engine.Engine) *TCPListener {
	return &TCPListener{
		addr:       addr,
		targetAddr: targetAddr,
		engine:     e,
	}
}

func (l *TCPListener) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", l.addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Printf("[Capture] TCP Listener started on %s -> %s\n", l.addr, l.targetAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				fmt.Printf("[Capture] Accept error: %v\n", err)
				continue
			}
		}

		go l.handleConnection(conn)
	}
}

func (l *TCPListener) handleConnection(src net.Conn) {
	defer src.Close()

	// Connect to target
	dst, err := net.Dial("tcp", l.targetAddr)
	if err != nil {
		fmt.Printf("[Capture] Failed to connect to target %s: %v\n", l.targetAddr, err)
		return
	}
	defer dst.Close()

	// Start bi-directional relay (local instance for metadata isolation)
	relay := proxy.NewRelay(l.engine, l.targetAddr, false)
	relay.Start(src, dst)
}

// GetLocalIP returns the primary non-loopback IPv4 address of the host.
func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}
