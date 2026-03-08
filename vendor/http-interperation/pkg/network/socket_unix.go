//go:build !windows

package network

import (
	"syscall"
)

// setSocketTTL sets the IP TTL option
func setSocketTTL(fd uintptr, ttl int) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
}

// setSocketWindowSize sets the TCP receive buffer size (Window Size)
func setSocketWindowSize(fd uintptr, size int) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
}
