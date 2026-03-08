package proxy

import (
	"net"
	"time"

	"github.com/bacot120211/netkit-go/pkg/logger"
)

// HandleBIND sets up a SOCKS5 BIND listener.
// 1. Listen on a random port.
// 2. Return the listen address.
// 3. Wait for the target to connect.
// 4. Return the connected address and the connection.
func HandleBIND(targetHost string) (net.Listener, string, error) {
	// 1. Listen on a random port
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, "", err
	}

	addr := l.Addr().String()
	_, port, _ := net.SplitHostPort(addr)

	// For SOCKS5 BIND, we need to return the local IP that the client can reach.
	// We use a helper or just 0.0.0.0 and let the handler decide.
	// Typically, we use the IP of the interface the client connected on.
	return l, port, nil
}

// WaitForBindConnection waits for the target host to connect to our bind listener.
func WaitForBindConnection(l net.Listener, targetHost string, timeout time.Duration) (net.Conn, error) {
	_ = l.(*net.TCPListener).SetDeadline(time.Now().Add(timeout))
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			return nil, err
		}

		remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

		// Security: Verify that the connection comes from the expected target host
		// (if targetHost was provided and is not empty/wildcard)
		if targetHost != "" && targetHost != "0.0.0.0" && targetHost != "::" {
			// Resolve targetHost to IPs to compare
			targetIPs, _ := net.LookupIP(targetHost)
			isAllowed := false
			for _, ip := range targetIPs {
				if ip.String() == remoteHost {
					isAllowed = true
					break
				}
			}
			if !isAllowed && remoteHost != targetHost {
				logger.Warnf("[SOCKS5] 🚫 BIND rejected unauthorized connection from %s (expected %s)\n", remoteHost, targetHost)
				conn.Close()
				continue
			}
		}

		logger.Infof("[SOCKS5] ✅ BIND connection accepted from %s\n", conn.RemoteAddr())
		return conn, nil
	}
}
