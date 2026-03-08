//go:build windows

package network

import (
	"syscall"
)

// setSocketTTL sets the IP TTL option
func setSocketTTL(fd uintptr, ttl int) error {
	// IPPROTO_IP = 0, IP_TTL = 4 (on Windows)
	// Using standard syscall package which maps fairly well, but need to be careful with OS differences.
	// Windows: syscall.IPPROTO_IP is 0. IP_TTL is 4.
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
}

// setSocketWindowSize sets the TCP receive buffer size (Window Size)
func setSocketWindowSize(fd uintptr, size int) error {
	// SOL_SOCKET = 65535 (Windows), SO_RCVBUF = 4098 (Windows)
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
}
