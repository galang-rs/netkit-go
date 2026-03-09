package manager

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync" // Added for mu sync.Mutex
	"time"

	"github.com/bacot120211/netkit-go/pkg/adblock" // Added
	"github.com/bacot120211/netkit-go/pkg/capture"
	"github.com/bacot120211/netkit-go/pkg/cgnat" // Added
	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/exporter"
	"github.com/bacot120211/netkit-go/pkg/interceptor"
	"github.com/bacot120211/netkit-go/pkg/js"
	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/proc"
	"github.com/bacot120211/netkit-go/pkg/protocol/discovery"
	"github.com/bacot120211/netkit-go/pkg/protocol/dns"
	"github.com/bacot120211/netkit-go/pkg/protocol/tls"
	"github.com/bacot120211/netkit-go/pkg/proxy"
	"github.com/bacot120211/netkit-go/pkg/security" // Added
	"github.com/bacot120211/netkit-go/pkg/tunnel"
)

type Manager struct {
	Config      *Config
	Engine      engine.Engine
	Runtime     *js.Runtime
	Sniffer     *capture.Sniffer
	HostsMgr    *proc.HostsManager
	RootCA      *tls.CA
	SNIList     *capture.SNIListener
	Transparent *interceptor.TransparentInterceptor
	Launcher    *proc.Launcher
	// Advanced Features
	AdBlock  *adblock.Engine
	CGNAT    *cgnat.Bypass
	Scope    *security.ScopeManager
	Limiter  *security.BruteforceLimiter
	Firewall *security.Firewall

	mu   sync.Mutex    // Added
	Done chan struct{} // Signal to main.go that we should exit
}

func NewManager(cfg *Config) *Manager {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	eng := engine.New()
	if cfg.WorkerCount > 0 {
		eng.SetWorkerCount(cfg.WorkerCount)
	}
	return &Manager{
		Config: cfg,
		Engine: eng,
		Done:   make(chan struct{}),
	}
}

func (m *Manager) Setup() error {
	// Initialize CA
	if err := m.setupCA(); err != nil {
		return fmt.Errorf("failed to setup CA: %w", err)
	}

	// Global MITM override
	if m.Config.MITMAll {
		m.Config.ShouldMITM = func(hostname string) bool {
			return true
		}
		logger.Printf("[Manager] 🔓 Full MITM Interception ENABLED (All domains will be intercepted)\n")
	}

	// Handle "WinDivert" (Driverless Transparent) mode
	if m.Config.WinDivert {
		m.Transparent = interceptor.NewTransparentInterceptor(m.Engine)
		m.Engine.RegisterInterceptor(m.Transparent)
	}

	// Register specialized interceptors
	m.Engine.RegisterInterceptor(&interceptor.JA3Interceptor{})

	// Setup Transparent Redirection & Pre-resolve IPs
	if m.Config.Transparent || m.Config.Domains != "" {
		m.HostsMgr = proc.NewHostsManager()
		if m.Config.Domains != "" {
			targetDomains := strings.Split(m.Config.Domains, ",")
			for i := range targetDomains {
				targetDomains[i] = strings.TrimSpace(targetDomains[i])
			}
			if err := m.HostsMgr.RedirectDomains(targetDomains); err != nil {
				return err
			}
			// Initialize Global Proxy Pool mapping for JS BEFORE starting JS scripts
			js.SetGlobalResolvedIPs(m.HostsMgr.ResolvedIPs)
		}
	}

	// Initialize JS Runtime
	runtime, err := js.NewRuntime()
	if err != nil {
		return fmt.Errorf("failed to create JS runtime: %w", err)
	}
	m.Runtime = runtime

	// Wire up dynamic domain registration
	if ce, ok := m.Engine.(interface{ SetOnDomain(func(string)) }); ok {
		ce.SetOnDomain(func(domain string) {
			m.RegisterDomain(domain)
		})
	}

	// Initialize JS Runtime with Engine and CA
	// Initialize JS Runtime with Security components
	m.Runtime.Initialize(m.Engine, m.RootCA, m.Firewall, m.Scope, m.Limiter)

	// JS Interception logic
	if m.Config.ScriptPath != "" {
		// m.Runtime is already initialized at the top of NewManager
		jsInt, err := js.NewJSInterceptor(m.Runtime, m.Config.ScriptPath, m.Engine, m.RootCA, m.Config.ShouldMITM)
		if err != nil {
			return fmt.Errorf("failed to load JS script %s: %w", m.Config.ScriptPath, err)
		}
		m.Engine.RegisterInterceptor(jsInt)
		logger.Printf("[Manager] Loaded JS script: %s\n", m.Config.ScriptPath)
	}

	// Setup Packet Inspector (Debug Mode)
	if m.Config.Debug {
		inspector := capture.NewPacketInspector(m.Config.Verbose)
		m.Engine.RegisterInterceptor(inspector)
		logger.Printf("[Manager] 🔍 Packet Inspector enabled (Debug mode)\n")
	}

	// Setup PCAP
	if m.Config.PcapPath != "" {
		pw, err := exporter.NewPCAPWriter(m.Config.PcapPath)
		if err != nil {
			logger.Printf("[Manager] Failed to create PCAP writer: %v\n", err)
		} else {
			m.Engine.SetPcapWriter(pw)
			logger.Printf("[Manager] PCAP logging to %s\n", m.Config.PcapPath)
		}
	}

	// Setup Filter
	if m.Config.FilterExpr != "" {
		m.Engine.SetFilter(&engine.Filter{Expression: m.Config.FilterExpr})
		logger.Printf("[Manager] Applied filter: %s\n", m.Config.FilterExpr)
	}

	// Setup Mirror
	if m.Config.MirrorAddr != "" {
		mir, err := proxy.NewMirror(m.Config.MirrorAddr)
		if err != nil {
			logger.Printf("[Manager] Failed to create mirror: %v\n", err)
		} else {
			m.Engine.AddMirror(mir)
			logger.Printf("[Manager] Mirroring traffic to %s\n", m.Config.MirrorAddr)
		}
	}

	// Initialize Advanced Latent Features
	if m.Config.AdBlock {
		m.AdBlock = adblock.GetEngine()
		logger.Infof("[Manager] AdBlock engine enabled")
	}

	m.Scope = security.NewScopeManager(security.RoleBoth)
	logger.Infof("[Manager] Security scope manager initialized (Role: Both)")

	// Register Security Interceptor
	m.Firewall = security.NewFirewall()
	secInt := security.NewSecurityInterceptor(m.Firewall, m.Scope)
	m.Engine.RegisterInterceptor(secInt)
	logger.Infof("[Manager] Security Interceptor registered (Firewall & Scope)")

	// Initialize Bruteforce Limiter
	m.Limiter = security.NewBruteforceLimiter(
		m.Config.BruteforceMaxAttempts,
		time.Duration(m.Config.BruteforceWindow)*time.Minute,
		time.Duration(m.Config.BruteforceBanDuration)*time.Minute,
	)
	logger.Infof("[Manager] Bruteforce limiter enabled (Max: %d, Window: %dm, Ban: %dm)",
		m.Config.BruteforceMaxAttempts, m.Config.BruteforceWindow, m.Config.BruteforceBanDuration)

	if m.Config.CGNATDetect {
		m.CGNAT = cgnat.NewBypass()
		if m.Config.MikroTikHost != "" {
			m.CGNAT.SetOnDetect(func(res *cgnat.BypassResult) {
				if res.RouterType == "MikroTik" {
					logger.Successf("[CGNAT] Auto-detected MikroTik at %s", m.Config.MikroTikHost)
				}
			})
		}
	}

	return nil
}

func (m *Manager) setupCA() error {
	certPath := "ca.crt"
	if m.Config.RootCAPath != "" {
		certPath = m.Config.RootCAPath
	}
	keyPath := "ca.key"
	if m.Config.RootKeyPath != "" {
		keyPath = m.Config.RootKeyPath
	}

	certData, errCert := os.ReadFile(certPath)
	keyData, errKey := os.ReadFile(keyPath)

	if errCert == nil && errKey == nil {
		logger.Printf("[Manager] Loading existing Root CA...\n")
		ca, err := tls.LoadCA(certData, keyData)
		if err == nil {
			m.RootCA = ca
			// Register CA in engine for listeners to serve it
			if ce, ok := m.Engine.(interface {
				SetCA(interface {
					GetCertPEM() []byte
				})
			}); ok {
				ce.SetCA(ca)
			}
			return nil
		}
		logger.Printf("[Manager] Failed to load existing CA: %v. Generating new one.\n", err)
	}

	logger.Printf("[Manager] Generating new Root CA...\n")
	ca, err := tls.NewCA()
	if err != nil {
		return err
	}
	m.RootCA = ca

	os.WriteFile(certPath, ca.GetCertPEM(), 0644)
	os.WriteFile(keyPath, ca.GetKeyPEM(), 0600)
	logger.Printf("[Manager] 🔥 NEW Root CA generated and saved (ca.crt, ca.key)\n")

	// Register CA in engine for listeners to serve it
	if ce, ok := m.Engine.(interface {
		SetCA(interface {
			GetCertPEM() []byte
		})
	}); ok {
		ce.SetCA(ca)
	}

	logger.Printf("[Manager] ⚠️  IMPORTANT: If you previous installed a CA, DELETE it from your system and install this new one!\n")

	absPath, _ := filepath.Abs(certPath)
	logger.Printf("[Manager] Root CA available at: %s\n", absPath)
	return nil
}

func (m *Manager) Start(ctx context.Context) error {
	// Auto-start listeners when -domains is used (traffic is redirected to 127.0.0.1)
	if m.Config.Domains != "" {
		if m.Config.TCPAddr == "" {
			m.Config.TCPAddr = ":80"
			logger.Printf("[Manager] 🔧 Auto-enabling TCP listener on :80 (domains mode)\n")
		}
		if m.Config.TLSAddr == "" {
			m.Config.TLSAddr = ":443"
			logger.Printf("[Manager] 🔧 Auto-enabling TLS listener on :443 (domains mode)\n")
		}
	}

	// Start Launcher if configured
	if m.Config.AppPath != "" {
		l, err := proc.NewLauncher(m.Config.AppPath)
		if err != nil {
			logger.Printf("[Manager] Failed to create launcher: %v\n", err)
		} else {
			m.Launcher = l
			pid, err := l.Start()
			if err != nil {
				logger.Printf("[Manager] Failed to start application: %v\n", err)
			} else {
				logger.Printf("[Manager] 🚀 Launched application: %s (PID: %d)\n", m.Config.AppPath, pid)
			}
		}
	}

	// Start Engine
	go func() {
		if err := m.Engine.Start(ctx); err != nil && err != context.Canceled {
			logger.Printf("[Manager] Engine error: %v\n", err)
		}
	}()

	// Start Transparent Redirection
	if m.Config.Transparent {
		if err := m.startTransparent(ctx); err != nil {
			logger.Printf("[Manager] Transparent mode error: %v\n", err)
		}
	}

	// Start Transparent Sniffer (raw socket, no proxy config needed)
	if m.Config.SniffAll || m.Config.IfaceAddr != "" {
		var sniffIPs []string
		localIPs := getLocalIPs()
		if m.Config.IfaceAddr != "" {
			sniffIPs = strings.Split(m.Config.IfaceAddr, ",")
			for i := range sniffIPs {
				sniffIPs[i] = strings.TrimSpace(sniffIPs[i])
			}
		} else if m.Config.SniffAll {
			sniffIPs = localIPs
		} else {
			sniffIPs = localIPs
		}
		if len(sniffIPs) > 0 {
			if err := m.Scope.Guard("capture"); err != nil {
				logger.Warnf("[Manager] 🚫 Feature 'capture' BLOCKED by security scope: %v", err)
			} else {
				m.Sniffer = capture.NewSniffer(sniffIPs, m.Engine)
				m.Sniffer.SetLocalIPs(localIPs)
				m.Sniffer.SniffAll = m.Config.SniffAll
				m.Sniffer.RawSniff = m.Config.RawSniff
				m.Sniffer.Verbose = m.Config.Verbose
				logger.Printf("[Sniffer] 🎯 Starting transparent capture on IPs: %v\n", sniffIPs)
				go func() {
					if err := m.Sniffer.Start(ctx); err != nil {
						logger.Printf("[Sniffer] Error: %v\n", err)
					}
				}()
			}
		} else {
			logger.Printf("[Sniffer] ⚠️  No local IPs found, transparent capture skipped\n")
		}
	}

	// Start Listeners
	if m.Config.TCPAddr != "" {
		var l interface{ Start(context.Context) error }
		if m.Config.Domains != "" {
			var resolved map[string]string
			if m.HostsMgr != nil {
				resolved = m.HostsMgr.ResolvedIPs
			}
			l = capture.NewHTTPListener(m.Config.TCPAddr, m.Engine, resolved)
		} else {
			tcpL := capture.NewTCPListener(m.Config.TCPAddr, m.Config.TCPTarget, m.Engine)
			l = tcpL
		}
		go l.Start(ctx)
	}

	// SOCKS5 (Explicitly handled from Listener struct)
	if m.Config.TCPAddr != "" && !strings.Contains(m.Config.TCPTarget, ":") && m.Config.TCPTarget == "socks5" {
		// This block is often handled in specialized listener configs,
		// but let's ensure we account for it if configured this way.
	}

	if m.Config.TLSAddr != "" {
		var l interface{ Start(context.Context) error }
		if m.Config.Domains != "" {
			var resolved map[string]string
			if m.HostsMgr != nil {
				resolved = m.HostsMgr.ResolvedIPs
			}
			// Transparent mode with domain redirection: use SNIListener to detect target host
			sniL := capture.NewSNIListener(m.Config.TLSAddr, m.RootCA, m.Engine, resolved)
			sniL.CapturesDir = m.Config.CapturesDir // wire passthrough capture dir
			sniL.ForceHTTP11 = m.Config.ForceHTTP11 // wire force http/1.1
			sniL.TLSSessionTicketKey = m.Config.TLSSessionTicketKey
			sniL.StrictInterceptDomains = m.Config.StrictInterceptDomains
			sniL.ShouldMITM = m.Config.ShouldMITM
			sniL.Verbose = m.Config.Verbose
			sniL.TLSInt.Verbose = m.Config.Verbose
			sniL.Sniffer = m.Sniffer
			m.SNIList = sniL
			l = sniL
		} else {
			// Fixed target mode: use standard TLSListener
			l = capture.NewTLSListener(m.Config.TLSAddr, m.Config.TLSTarget, "", m.RootCA, m.Engine)
		}
		go l.Start(ctx)
	}

	// Start HTTP/HTTPS MITM Proxy (optional, untuk decrypt HTTPS)
	if m.Config.HTTPProxyAddr != "" {
		if err := m.Scope.Guard("proxy_http"); err != nil {
			logger.Warnf("[Manager] 🚫 Feature 'proxy_http' BLOCKED by security scope: %v", err)
		} else {
			var resolved map[string]string
			if m.HostsMgr != nil {
				resolved = m.HostsMgr.ResolvedIPs
			}
			l := capture.NewHTTPProxyListener(m.Config.HTTPProxyAddr, m.RootCA, m.Engine, resolved)
			l.ShouldMITM = m.Config.ShouldMITM
			l.Limiter = m.Limiter // Passthrough limiter
			go l.Serve(ctx)
		}
	}

	// Start UDP Listener
	if m.Config.UDPAddr != "" && m.Config.UDPTarget != "" {
		l := capture.NewUDPListener(m.Config.UDPAddr, m.Config.UDPTarget, m.Engine)
		go func() {
			if err := l.Start(ctx); err != nil {
				logger.Printf("[Manager] UDP Listener Error: %v\n", err)
			}
		}()
	}

	// Start HTTP/3 Listener
	if m.Config.H3Addr != "" {
		l := capture.NewH3Listener(m.Config.H3Addr, m.RootCA, m.Engine)
		logger.Infof("[H3] 🚀 HTTP/3 Listener starting on %s\n", m.Config.H3Addr)
		go func() {
			if err := l.Start(ctx); err != nil {
				logger.Printf("[Manager] H3 Listener Error: %v\n", err)
			}
		}()
	}

	// Start DNS Spoofing
	if m.Config.DNSSpoof {
		if err := m.Scope.Guard("dns_spoof"); err != nil {
			logger.Warnf("[Manager] 🚫 Feature 'dns_spoof' BLOCKED by security scope: %v", err)
		} else {
			dnsS := dns.NewDNSSpoofer(m.Engine)
			// If we are redirecting domains, add them to the DNS spoofer
			if m.Config.Domains != "" {
				domains := strings.Split(m.Config.Domains, ",")
				for _, d := range domains {
					dnsS.AddHost(strings.TrimSpace(d), "127.0.0.1")
				}
			}
			go dnsS.Start(ctx)
		}
	}

	// Start Discovery
	if m.Config.Discovery {
		if err := m.Scope.Guard("discovery"); err != nil {
			logger.Warnf("[Manager] 🚫 Feature 'discovery' BLOCKED by security scope: %v", err)
		} else {
			disc := discovery.NewServiceDiscovery(m.Sniffer)
			disc.Verbose = m.Config.Verbose
			go disc.Start(ctx)
		}
	}

	// Handle "WinDivert" (Driverless Transparent) mode
	if m.Config.WinDivert {
		if err := m.Transparent.Start(); err == nil {
			// Example: Redirect common ports to our local MITM listener
			// Note: Port 433 -> 127.0.0.1:443 (SNIListener)
			// This is useful if we also use DNS spoofing to point target IPs to local.
			_ = m.Transparent.RedirectTCP("0.0.0.0", 443, "127.0.0.1", 443)
			_ = m.Transparent.RedirectTCP("0.0.0.0", 80, "127.0.0.1", 80)
		}
	}

	// Start NK-Tunnel Server
	if m.Config.TunnelServerAddr != "" {
		if err := m.Scope.Guard("tunnel_server"); err != nil {
			logger.Warnf("[Manager] 🚫 Feature 'tunnel_server' BLOCKED by security scope: %v", err)
		} else {
			srv := tunnel.NewNKTunnelServer(m.Config.TunnelServerAddr, func(u, p string) bool {
				// Check against configured credentials
				return u == m.Config.TunnelUser && p == m.Config.TunnelPass
			}, m.Engine, m.RootCA, m.Config.TunnelPortRange)
			go func() {
				if err := srv.Start(); err != nil {
					logger.Printf("[Manager] Tunnel Server Error: %v\n", err)
				}
			}()
		}
	}

	// Start NK-Tunnel Client
	if m.Config.TunnelClientTo != "" {
		if err := m.Scope.Guard("tunnel_client"); err != nil {
			logger.Warnf("[Manager] 🚫 Feature 'tunnel_client' BLOCKED by security scope: %v", err)
		} else {
			parts := strings.Split(m.Config.TunnelClientTo, ":")
			if len(parts) >= 5 {
				server := parts[0] + ":" + parts[1]
				user := parts[2]
				pass := parts[3]

				var remoteRange, proto, localAddr string
				p4 := strings.ToLower(parts[4])
				// If 5th part is a protocol, remote is auto (0)
				if p4 == "tcp" || p4 == "udp" || p4 == "https" || p4 == "all" {
					remoteRange = "0"
					proto = p4
					if len(parts) >= 6 {
						localAddr = strings.Join(parts[5:], ":")
					}
				} else {
					remoteRange = parts[4]
					if len(parts) >= 6 {
						proto = parts[5]
					}
					if len(parts) >= 7 {
						localAddr = strings.Join(parts[6:], ":")
					}
				}

				if localAddr == "" {
					localAddr = m.Config.HTTPProxyAddr
				}
				if localAddr == "" {
					localAddr = "127.0.0.1:8080" // Fallback
				}

				cli := tunnel.NewNKTunnelClient(server, user, pass, localAddr, remoteRange, proto)
				go func() {
					if err := cli.Start(); err != nil {
						logger.Printf("[Manager] Tunnel Client Error: %v\n", err)
					}
				}()
			} else {
				logger.Printf("[Manager] Invalid tunnel format: %s\n", m.Config.TunnelClientTo)
			}
		}
	}

	// Start NK-Tunnel Client
	if m.Config.H3Addr != "" {
		m.startH3Listener(ctx)
	}

	// CGNAT Discovery (if enabled)
	if m.Config.CGNATDetect && m.CGNAT != nil {
		go func() {
			logger.Infof("[CGNAT] Starting network auto-detection...")
			res := m.CGNAT.AutoDetect(context.Background())
			if res.Error != nil {
				logger.Errorf("[CGNAT] Detection failed: %v", res.Error)
			} else {
				logger.Successf("[CGNAT] NAT: %s, Network: %s, Router: %s", res.NATType, res.NetworkType, res.RouterType)
				if m.Config.MikroTikHost != "" && res.RouterType == "MikroTik" {
					// Automatic MikroTik port forwarding example
					mt := cgnat.NewMikroTikBypass(m.Config.MikroTikHost, m.Config.MikroTikUser, m.Config.MikroTikPass)
					logger.Infof("[MikroTik] Attempting API connection to %s...", m.Config.MikroTikHost)
					if err := mt.EnableUPnP(); err != nil {
						logger.Warnf("[MikroTik] Failed to enable UPnP: %v", err)
					} else {
						logger.Successf("[MikroTik] UPnP enabled successfully")
					}
				}
			}
		}()
	}

	return nil
}

func (m *Manager) generateRandom(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func (m *Manager) getPort(addr string) int {
	_, portStr, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(portStr)
	return p
}

func (m *Manager) startTransparent(ctx context.Context) error {
	// Already handled in Setup()
	return nil
}

func (m *Manager) Stop() {
	if m.Transparent != nil {
		m.Transparent.Cleanup()
	}
	if m.HostsMgr != nil {
		m.HostsMgr.Restore()
	}
	m.Engine.Stop()
}

func (m *Manager) startH3Listener(ctx context.Context) {
	if m.Config.H3Addr == "" {
		return
	}
	l := capture.NewH3Listener(m.Config.H3Addr, m.RootCA, m.Engine)
	go func() {
		if err := l.Start(ctx); err != nil {
			logger.Errorf("[H3] Listener error: %v", err)
		}
	}()
}

func (m *Manager) RegisterDomain(domain string) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return
	}

	logger.Printf("[Manager] 🌐 Registering new domain: %s\n", domain)

	if domain == "*" {
		logger.Printf("[Manager] 🔓 Global intercept enabled via Domain(\"*\")\n")
		m.Config.MITMAll = true
		m.Config.ShouldMITM = func(hostname string) bool { return true }
		if m.SNIList != nil {
			m.SNIList.ShouldMITM = m.Config.ShouldMITM
			m.SNIList.AddStrictDomain("*")
		}
		if m.Runtime != nil {
			m.Runtime.ShouldMITM = m.Config.ShouldMITM
		}
		return
	}

	// 1. Add to HostsManager (for transparent redirection)
	if m.HostsMgr != nil {
		_ = m.HostsMgr.RedirectDomains([]string{domain})
	}

	// 2. Add to SNIListener (for TLS interception)
	if m.SNIList != nil {
		m.SNIList.AddStrictDomain(domain)
	}
}

// getLocalIPs returns all active IPv4/IPv6 addresses on this machine, including loopback.
func getLocalIPs() []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			ips = append(ips, ip.String())
		}
	}
	return ips
}
