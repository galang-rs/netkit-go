package capture

import (
	"context"
	"fmt"
	"net"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/protocol/tls"
)

type TLSListener struct {
	addr        string
	targetAddr  string
	hostname    string
	engine      engine.Engine
	interceptor *tls.TLSInterceptor
}

func NewTLSListener(addr, targetAddr, hostname string, ca *tls.CA, e engine.Engine) *TLSListener {
	return &TLSListener{
		addr:        addr,
		targetAddr:  targetAddr,
		hostname:    hostname,
		engine:      e,
		interceptor: tls.NewTLSInterceptor(ca, e),
	}
}

func (l *TLSListener) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", l.addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Printf("[Capture] TLS MITM Listener started on %s -> %s (as %s)\n", l.addr, l.targetAddr, l.hostname)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				logger.Printf("[Capture] Accept error: %v\n", err)
				continue
			}
		}

		go func(c net.Conn) {
			localAddr := c.LocalAddr().String()
			localHost, _, _ := net.SplitHostPort(localAddr)

			connInfo := &engine.ConnInfo{
				Type:    "tls_listener",
				Source:  c.RemoteAddr().String(),
				Dest:    l.targetAddr,
				IP:      c.RemoteAddr().String(),
				Through: engine.GetIPType(localHost),
			}
			_ = l.interceptor.HandleMITM(c, l.targetAddr, l.hostname, nil, nil, connInfo)
		}(conn)
	}
}
