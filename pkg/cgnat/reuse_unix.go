//go:build !windows
// +build !windows

package cgnat

import "syscall"

// reusePortControl sets SO_REUSEADDR and SO_REUSEPORT on Unix systems.
func reusePortControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 0xf /* SO_REUSEPORT */, 1)
	})
}
