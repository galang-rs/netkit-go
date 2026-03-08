package proc

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

var HostsPath = `C:\Windows\System32\drivers\etc\hosts`
var Marker = "# [REVERSE-ENGINE-REDIRECT]"

type HostsManager struct {
	originalContent []string
	ResolvedIPs     map[string]string
}

func NewHostsManager() *HostsManager {
	return &HostsManager{
		ResolvedIPs: make(map[string]string),
	}
}

// publicDNSResolver creates a resolver that uses public DNS servers directly,
// bypassing system DNS (which may be broken by hosts file or WireGuard routing).
func publicDNSResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			publicDNS := []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}
			d := net.Dialer{Timeout: 3 * time.Second}
			for _, dns := range publicDNS {
				conn, err := d.DialContext(ctx, "udp4", dns)
				if err == nil {
					return conn, nil
				}
			}
			return d.DialContext(ctx, "udp4", address)
		},
	}
}

func (h *HostsManager) RedirectDomains(domains []string) error {
	// 1. Pre-resolve IPs using PUBLIC DNS (bypass system DNS)
	fmt.Println("[Hosts] Pre-resolving domains using public DNS (8.8.8.8/1.1.1.1)...")
	resolver := publicDNSResolver()

	for _, d := range domains {
		if d == "localhost" || d == "127.0.0.1" || d == "::1" {
			continue
		}
		// Use a per-domain timeout to avoid hanging forever
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := resolver.LookupIPAddr(ctx, d)
		cancel()

		if err != nil {
			fmt.Printf("[Hosts]   ⚠️  %s -> FAILED: %v\n", d, err)
			continue
		}

		// Find first IPv4
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				h.ResolvedIPs[d] = ip.IP.String()
				fmt.Printf("[Hosts]   %s -> %s\n", d, ip.IP.String())
				break
			}
		}
	}

	if len(h.ResolvedIPs) == 0 {
		fmt.Println("[Hosts] ⚠️  WARNING: No domains could be resolved! DNS may be completely blocked.")
		fmt.Println("[Hosts] ⚠️  MITM will fail. Check internet connectivity and DNS access.")
	}

	// 2. Read existing hosts
	file, err := os.Open(HostsPath)
	if err != nil {
		return fmt.Errorf("failed to open hosts file (run as Admin?): %v", err)
	}

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, Marker) {
			lines = append(lines, line)
		}
	}
	file.Close()

	h.originalContent = append([]string(nil), lines...) // Backup

	// 3. Add new redirects
	for _, d := range domains {
		lines = append(lines, fmt.Sprintf("127.0.0.1 %s %s", d, Marker))
		lines = append(lines, fmt.Sprintf("::1 %s %s", d, Marker))
	}

	fmt.Println("[Hosts] Applied redirection to 127.0.0.1")
	return os.WriteFile(HostsPath, []byte(strings.Join(lines, "\r\n")+"\r\n"), 0644)
}

func (h *HostsManager) Restore() error {
	file, err := os.Open(HostsPath)
	if err != nil {
		return err
	}

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, Marker) {
			lines = append(lines, line)
		}
	}
	file.Close()

	fmt.Println("[Hosts] Restoring original hosts file content...")
	return os.WriteFile(HostsPath, []byte(strings.Join(lines, "\r\n")+"\r\n"), 0644)
}
