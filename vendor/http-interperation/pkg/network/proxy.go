package network

import (
	"golang.org/x/net/proxy"
)

// ParseProxy is a stub as proxy support has been removed.
// It always returns an empty string and nil auth.
func ParseProxy(proxyStr string) (string, *proxy.Auth) {
	return "", nil
}
