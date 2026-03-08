package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// HappyDialer implements RFC 8305 Happy Eyeballs
type HappyDialer struct {
	Delay time.Duration
}

func NewHappyDialer() *HappyDialer {
	return &HappyDialer{
		Delay: 250 * time.Millisecond,
	}
}

func (h *HappyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	var ipv4s, ipv6s []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4s = append(ipv4s, ip)
		} else {
			ipv6s = append(ipv6s, ip)
		}
	}

	// Channel to receive the first successful connection
	type result struct {
		conn net.Conn
		err  error
	}
	resChan := make(chan result, len(ips))
	done := make(chan struct{})
	defer close(done)

	var wg sync.WaitGroup

	// Helper to attempt connection
	attempt := func(ip net.IP) {
		defer wg.Done()
		addr := net.JoinHostPort(ip.String(), port)
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, network, addr)

		select {
		case resChan <- result{conn, err}:
		case <-done:
			if conn != nil {
				conn.Close()
			}
		}
	}

	// Start IPv6 attempts first
	for _, ip := range ipv6s {
		wg.Add(1)
		go attempt(ip)

		// Small delay before next attempt
		timer := time.NewTimer(h.Delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
	}

	// Then IPv4 attempts
	for _, ip := range ipv4s {
		wg.Add(1)
		go attempt(ip)

		timer := time.NewTimer(h.Delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
	}

	// Wait for first success
	go func() {
		wg.Wait()
		resChan <- result{nil, fmt.Errorf("all connection attempts failed")}
	}()

	for range ips {
		res := <-resChan
		if res.err == nil && res.conn != nil {
			return res.conn, nil
		}
	}

	return nil, fmt.Errorf("failed to connect to %s", address)
}
