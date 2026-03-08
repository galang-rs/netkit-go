package cgnat

import "syscall"

// reusePortControl sets SO_REUSEADDR on Windows (SO_REUSEPORT not available).
func reusePortControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
}
