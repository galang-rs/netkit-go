package capture

import (
	"context"
	"net"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/proxy"
)

type UDPListener struct {
	addr       string
	targetAddr string
	engine     engine.Engine
}

func NewUDPListener(addr, targetAddr string, e engine.Engine) *UDPListener {
	return &UDPListener{
		addr:       addr,
		targetAddr: targetAddr,
		engine:     e,
	}
}

func (l *UDPListener) Start(ctx context.Context) error {
	// ... (rest is same)
	relay := proxy.NewUDPRelay(l.engine)
	host, _, _ := net.SplitHostPort(l.addr)
	relay.RegisterConn(&engine.ConnInfo{
		Type:    "udp",
		Source:  l.addr, // Simplified, might want actual client addr if available
		Dest:    l.targetAddr,
		IP:      l.addr,
		Through: engine.GetIPType(host),
	})

	logger.Printf("[Capture] UDP Listener started on %s -> %s\n", l.addr, l.targetAddr)

	// UDPRelay.Start is blocking, so we run it in a goroutine if we want to support multiple
	// or just return if it handles its own loop.
	// Our UDPRelay handles session multiplexing internally.

	errChan := make(chan error, 1)
	go func() {
		errChan <- relay.Start(l.addr, l.targetAddr)
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errChan:
		return err
	}
}
