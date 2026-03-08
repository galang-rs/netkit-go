package browser

import (
	"bufio"
	"math/rand"
	"os"
	"sync"
	"time"

	"http-interperation/pkg/network"

	fhttp "github.com/bogdanfinn/fhttp"
)

// UserAgentProvider manages User-Agent strings
type UserAgentProvider struct {
	userAgents []string
	mu         sync.RWMutex
}

// Global provider instance
var globalUAProvider *UserAgentProvider
var uaOnce sync.Once

// GetUserAgentProvider returns the singleton provider
func GetUserAgentProvider() *UserAgentProvider {
	uaOnce.Do(func() {
		globalUAProvider = &UserAgentProvider{
			userAgents: DefaultUserAgents,
		}
	})
	return globalUAProvider
}

// GetRandom returns a random User-Agent
func (p *UserAgentProvider) GetRandom() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.userAgents) == 0 {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}
	return p.userAgents[rand.Intn(len(p.userAgents))]
}

// LoadFromFile loads User-Agents from a file (one per line)
func (p *UserAgentProvider) LoadFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var newUAs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ua := scanner.Text()
		if ua != "" {
			newUAs = append(newUAs, ua)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if len(newUAs) > 0 {
		p.mu.Lock()
		p.userAgents = newUAs
		p.mu.Unlock()
	}
	return nil
}

// LoadFromURL fetches User-Agents from a URL
func (p *UserAgentProvider) LoadFromURL(url string) error {
	// Basic profile for bootstrapping to avoid circular dependecies
	tlsProfile := &network.TLSProfile{
		Name:              "UserAgentBootstrap",
		InitialWindowSize: 6291456,
		MaxFrameSize:      16384,
		HeaderTableSize:   65536,
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
	}

	transport, err := network.NewAdaptiveTransport(tlsProfile, nil, "", nil)
	if err != nil {
		return err
	}

	client := &fhttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var newUAs []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		ua := scanner.Text()
		if ua != "" {
			newUAs = append(newUAs, ua)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if len(newUAs) > 0 {
		p.mu.Lock()
		p.userAgents = newUAs
		p.mu.Unlock()
	}
	return nil
}

// DefaultUserAgents is a fallback list of modern User-Agents
var DefaultUserAgents = []string{
	// Chrome Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
	// Chrome MacOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	// Firefox Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	// Firefox MacOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
	// Safari MacOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	// Edge Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
}
