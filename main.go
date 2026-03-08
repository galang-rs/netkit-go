package main

import (
	"context"
	"flag"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/manager"
	"github.com/bacot120211/netkit-go/pkg/perf"
)

func isAdmin() bool {
	if runtime.GOOS != "windows" {
		return true
	}
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func main() {
	// Call Performance Optimizer early with temporary default or parsed config if possible.
	// We need flags parsed first to get custom maxprocs.
	cfg := manager.DefaultConfig()

	flag.IntVar(&cfg.WorkerCount, "workers", 0, "Number of packet processing workers (0 = auto)")
	flag.IntVar(&cfg.MaxProcs, "maxprocs", 0, "GOMAXPROCS setting (0 = all cores)")

	flag.StringVar(&cfg.PcapPath, "pcap", "", "Path to PCAP output file")
	flag.StringVar(&cfg.ScriptPath, "script", "scripts/log.js", "Path to JS script")
	flag.StringVar(&cfg.TCPAddr, "tcp", "", "TCP MITM listen address")
	flag.StringVar(&cfg.TCPTarget, "tcp-target", "", "TCP MITM target address")
	flag.StringVar(&cfg.TLSAddr, "tls", "", "TLS MITM listen address")
	flag.StringVar(&cfg.TLSTarget, "tls-target", "", "TLS MITM target address")
	flag.StringVar(&cfg.IfaceAddr, "iface", "", "Local IP address to bind for transparent capture (optional)")
	flag.StringVar(&cfg.FilterExpr, "filter", "", "Packet filter expression")
	flag.StringVar(&cfg.MirrorAddr, "mirror", "", "Mirror traffic to this UDP address")
	flag.StringVar(&cfg.AppPath, "app", "", "Path to application to launch and track")
	flag.BoolVar(&cfg.SniffAll, "sniff-all", false, "By-pass PID-specific filtering")
	flag.BoolVar(&cfg.Transparent, "transparent", false, "Enable transparent HTTPS redirection")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&cfg.MITMAll, "mitm-all", false, "Intercept all domains (auto-detect HTTPS)")
	flag.StringVar(&cfg.Domains, "domains", "", "Comma-separated list of domains to redirect")
	flag.StringVar(&cfg.UDPAddr, "udp", "", "UDP MITM listen address")
	flag.StringVar(&cfg.UDPTarget, "udp-target", "", "UDP target address for packet forwarding")
	flag.StringVar(&cfg.H3Addr, "h3", "", "HTTP/3 listener address (e.g. :443)")
	flag.BoolVar(&cfg.Debug, "debug", false, "Enable debug/packet inspector mode")

	// Latent Features Flags
	flag.BoolVar(&cfg.AdBlock, "adblock", false, "Enable AdBlock engine")
	flag.BoolVar(&cfg.CGNATDetect, "cgnat", false, "Enable CGNAT detection and bypass")
	flag.StringVar(&cfg.MikroTikHost, "mikrotik-host", "", "MikroTik API host")
	flag.StringVar(&cfg.MikroTikUser, "mikrotik-user", "", "MikroTik API username")
	flag.StringVar(&cfg.MikroTikPass, "mikrotik-pass", "", "MikroTik API password")

	flag.BoolVar(&cfg.WinDivert, "windivert", false, "Enable WinDivert transparent interception")
	flag.BoolVar(&cfg.DNSSpoof, "dns-spoof", false, "Enable DNS spoofing")
	flag.BoolVar(&cfg.Discovery, "discovery", false, "Enable mDNS, SSDP, and NBNS discovery")
	flag.BoolVar(&cfg.HappyEyeballs, "happy-eyeballs", false, "Enable Happy Eyeballs (multi-IP fallback)")
	flag.BoolVar(&cfg.RawSniff, "raw", false, "Enable raw byte capture")
	flag.BoolVar(&cfg.DomainToIPLink, "link-domains", false, "Map IPs to domains in logs")
	flag.BoolVar(&cfg.ForceHTTP11, "force-h11", false, "Force HTTP/1.1 (disable H2/H3)")

	flag.StringVar(&cfg.TunnelServerAddr, "tunnel-server", "", "Run NK-Tunnel server on this address (e.g. :9090)")
	flag.StringVar(&cfg.TunnelPortRange, "tunnel-server-range", "8000-8010", "Port range for tunnel server (e.g. 8000-8010)")
	flag.StringVar(&cfg.TunnelUser, "tunnel-user", "admin", "Username for NK-Tunnel")
	flag.StringVar(&cfg.TunnelPass, "tunnel-pass", "secret", "Password for NK-Tunnel")
	flag.StringVar(&cfg.TunnelClientTo, "tunnel", "", "Connect to NK-Tunnel server (format: ip:port:user:pass:remote_port:type)")

	listIfaces := flag.Bool("list-ifaces", false, "List all available network interfaces and IPs, then exit")
	flag.Parse()

	// Apply CPU optimizations after parsing flags
	perf.OptimizeCPU(cfg.MaxProcs)

	logger.Enabled = cfg.Verbose

	if *listIfaces {
		ifaces, err := net.Interfaces()
		if err != nil {
			logger.Errorf("Error: %v\n", err)
			os.Exit(1)
		}
		logger.Infof("Available Interfaces:\n")
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			logger.Infof("[%d] %s (MTU: %d)\n", iface.Index, iface.Name, iface.MTU)
			for _, addr := range addrs {
				logger.Infof("  └─ %s\n", addr.String())
			}
		}
		os.Exit(0)
	}

	logger.Infof("=== NetKit-Go Loading ===\n")

	if !isAdmin() {
		logger.Warnf("[WARNING] Not running as Administrator. Some features will fail.\n")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := manager.NewManager(cfg)
	if err := m.Setup(); err != nil {
		logger.Errorf("[ERROR] Setup failed: %v\n", err)
		os.Exit(1)
	}

	if err := m.Start(ctx); err != nil {
		logger.Errorf("[ERROR] Start failed: %v\n", err)
		os.Exit(1)
	}

	logger.Infof("[Main] Engine running. Press Ctrl+C to stop.\n")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigChan:
		logger.Warnf("\n[Main] User interrupt detected.\n")
	case <-m.Done:
		logger.Infof("\n[Main] Objective completed (Auto-shutdown).\n")
	}

	logger.Infof("\n[Main] Shutting down...\n")
	m.Stop()
	cancel()
}
