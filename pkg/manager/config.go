package manager

type Config struct {
	PcapPath      string
	ScriptPath    string
	TCPAddr       string
	TCPTarget     string
	TLSAddr       string
	TLSTarget     string
	HTTPProxyAddr string // HTTP/HTTPS MITM proxy (dynamic, browser-configured)
	FilterExpr    string
	MirrorAddr    string
	RootCAPath    string
	RootKeyPath   string
	UDPAddr       string
	UDPTarget     string
	H3Addr        string
	Debug         bool

	// Latent Features
	AdBlock      bool
	CGNATDetect  bool
	MikroTikHost string
	MikroTikUser string
	MikroTikPass string
	Passive      bool
	Transparent  bool
	Verbose      bool
	Domains      string
	SniffAll     bool
	AppPath      string
	IfaceAddr    string
	// CapturesDir: if non-empty, raw passthrough bytes (encrypted TLS) are saved here
	// even for strict clients that bypass MITM. E.g. "./captures"
	CapturesDir string
	// ForceHTTP11: if true, forces the TLS interceptor to negotiate HTTP/1.1
	// and blocks H2/H3 to simplify SSE/streaming decryption.
	ForceHTTP11 bool

	// TLSSessionTicketKey: if provided (32 bytes), used for TLS session tickets
	// to enable session resumption across connections.
	TLSSessionTicketKey string

	// Advanced Features
	WinDivert      bool
	DNSSpoof       bool
	Discovery      bool // mDNS, SSDP, NBNS
	HappyEyeballs  bool
	RawSniff       bool // Raw byte capture
	DomainToIPLink bool // Map remote IPs back to domains

	StrictInterceptDomains []string
	MITMAll                bool
	ShouldMITM             func(hostname string) bool

	// NK-Tunnel Features
	TunnelServerAddr string
	TunnelPortRange  string // Default range for dynamic allocation (e.g., "8000-8010")
	TunnelClientTo   string // Combined format or base for client
	TunnelUser       string
	TunnelPass       string

	// Security Features
	BruteforceMaxAttempts int
	BruteforceWindow      int // Minutes
	BruteforceBanDuration int // Minutes

	// Worker Settings
	WorkerCount int
	MaxProcs    int
}

func DefaultConfig() *Config {
	return &Config{
		ScriptPath:            "scripts/log.js",
		TunnelPortRange:       "8000-8010",
		BruteforceMaxAttempts: 5,
		BruteforceWindow:      10,
		BruteforceBanDuration: 30,
	}
}
