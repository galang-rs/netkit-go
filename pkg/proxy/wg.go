package proxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/bacot120211/netkit-go/pkg/logger"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	wgManager *WGManager
	wgOnce    sync.Once
)

type WGManager struct {
	mu       sync.RWMutex
	networks map[string]*WGNetwork
}

type WGNetwork struct {
	Netstack *netstack.Net
	Device   *device.Device
	Config   *WGConfig
	LastUsed time.Time
}

type WGConfig struct {
	PrivateKey string
	PublicKey  string
	Endpoint   string
	Address    []string
	DNS        []string
	MTU        int
	KeepAlive  int
}

func GetWGManager() *WGManager {
	wgOnce.Do(func() {
		wgManager = &WGManager{
			networks: make(map[string]*WGNetwork),
		}
		// Periodically clean up old networks
		go wgManager.cleanup()
	})
	return wgManager
}

func (m *WGManager) cleanup() {
	ticker := time.NewTicker(30 * time.Minute)
	for range ticker.C {
		m.mu.Lock()
		for hash, nw := range m.networks {
			if time.Since(nw.LastUsed) > 1*time.Hour {
				logger.Printf("[WG] 🧹 Closing idle network: %s\n", hash[:8])
				nw.Device.Close()
				delete(m.networks, hash)
			}
		}
		m.mu.Unlock()
	}
}

func (m *WGManager) DialContext(ctx context.Context, network, address, configStr string) (net.Conn, error) {
	nw, err := m.getOrCreateNetwork(configStr)
	if err != nil {
		return nil, err
	}
	return nw.Netstack.DialContext(ctx, network, address)
}

func (m *WGManager) getOrCreateNetwork(configStr string) (*WGNetwork, error) {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(configStr)))

	m.mu.RLock()
	nw, ok := m.networks[hash]
	m.mu.RUnlock()

	if ok {
		nw.LastUsed = time.Now()
		return nw, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double check
	if nw, ok = m.networks[hash]; ok {
		nw.LastUsed = time.Now()
		return nw, nil
	}

	cfg, err := parseWGConfig(configStr)
	if err != nil {
		return nil, err
	}

	logger.Printf("[WG] 🆕 Creating new network for endpoint %s\n", cfg.Endpoint)

	var localAddrs []netip.Addr
	for _, a := range cfg.Address {
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(a)); err == nil {
			localAddrs = append(localAddrs, prefix.Addr())
		} else if ip, err := netip.ParseAddr(strings.TrimSpace(a)); err == nil {
			localAddrs = append(localAddrs, ip)
		}
	}

	var dnsAddrs []netip.Addr
	for _, d := range cfg.DNS {
		if ip, err := netip.ParseAddr(strings.TrimSpace(d)); err == nil {
			dnsAddrs = append(dnsAddrs, ip)
		}
	}
	if len(dnsAddrs) == 0 {
		dnsAddrs = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1280
	}

	tun, tnet, err := netstack.CreateNetTUN(localAddrs, dnsAddrs, mtu)
	if err != nil {
		return nil, fmt.Errorf("netstack error: %w", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "[WG] "))

	// Convert keys to hex for IpcSet
	privHex := keyToHex(cfg.PrivateKey)
	pubHex := keyToHex(cfg.PublicKey)

	// Resolve endpoint hostname to IP
	host, port, err := net.SplitHostPort(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("failed to resolve wg endpoint %s: %v", host, err)
	}
	resolvedEndpoint := net.JoinHostPort(ips[0].String(), port)

	ipcConfig := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\n",
		privHex, pubHex, resolvedEndpoint)
	if cfg.KeepAlive > 0 {
		ipcConfig += fmt.Sprintf("persistent_keepalive_interval=%d\n", cfg.KeepAlive)
	}

	if err := dev.IpcSet(ipcConfig); err != nil {
		dev.Close()
		return nil, fmt.Errorf("ipc error: %w", err)
	}
	dev.Up()

	nw = &WGNetwork{
		Netstack: tnet,
		Device:   dev,
		Config:   cfg,
		LastUsed: time.Now(),
	}
	m.networks[hash] = nw
	return nw, nil
}

func parseWGConfig(s string) (*WGConfig, error) {
	cfg := &WGConfig{MTU: 1280}
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])

		switch key {
		case "privatekey":
			cfg.PrivateKey = val
		case "publickey":
			cfg.PublicKey = val
		case "endpoint":
			cfg.Endpoint = val
		case "address":
			cfg.Address = strings.Split(val, ",")
		case "dns":
			cfg.DNS = strings.Split(val, ",")
		case "mtu":
			fmt.Sscanf(val, "%d", &cfg.MTU)
		case "persistentkeepalive":
			fmt.Sscanf(val, "%d", &cfg.KeepAlive)
		}
	}
	if cfg.PrivateKey == "" || cfg.PublicKey == "" || cfg.Endpoint == "" {
		return nil, fmt.Errorf("invalid wg config: missing essential fields")
	}
	return cfg, nil
}

func keyToHex(base64Key string) string {
	decoded, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(decoded)
}
