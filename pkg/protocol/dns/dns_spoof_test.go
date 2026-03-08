package dns

import (
	"testing"

	"github.com/bacot120211/netkit-go/pkg/engine"
)

func TestNewDNSSpoofer(t *testing.T) {
	e := engine.New()
	d := NewDNSSpoofer(e)
	if d == nil {
		t.Fatal("NewDNSSpoofer should return non-nil")
	}
	if d.upstreamDNS != "8.8.8.8:53" {
		t.Errorf("expected upstream DNS '8.8.8.8:53', got '%s'", d.upstreamDNS)
	}
}

func TestDNSSpoofer_AddHost(t *testing.T) {
	e := engine.New()
	d := NewDNSSpoofer(e)

	d.AddHost("test.com", "127.0.0.1")
	d.AddHost("evil.com", "192.168.1.1")

	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.hosts["test.com"] != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got '%s'", d.hosts["test.com"])
	}
	if d.hosts["evil.com"] != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got '%s'", d.hosts["evil.com"])
	}
}

func TestDNSSpoofer_AddHost_Overwrite(t *testing.T) {
	e := engine.New()
	d := NewDNSSpoofer(e)

	d.AddHost("test.com", "1.2.3.4")
	d.AddHost("test.com", "5.6.7.8")

	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.hosts["test.com"] != "5.6.7.8" {
		t.Errorf("expected overwritten IP '5.6.7.8', got '%s'", d.hosts["test.com"])
	}
}

func TestDNSSpoofer_BuildResponse_ValidFormat(t *testing.T) {
	e := engine.New()
	d := NewDNSSpoofer(e)

	// Build a minimal DNS query for "test.com"
	query := buildDNSQuery("test.com")
	resp := d.buildResponse(query, "127.0.0.1")

	if len(resp) < len(query)+12 {
		t.Errorf("response too short: %d bytes", len(resp))
	}

	// Check response flags
	if resp[2] != 0x81 || resp[3] != 0x80 {
		t.Errorf("response flags: got 0x%02x%02x, want 0x8180", resp[2], resp[3])
	}

	// Check answer count
	if resp[7] != 1 {
		t.Errorf("expected 1 answer, got %d", resp[7])
	}
}

func TestDNSSpoofer_HostsMapEmpty(t *testing.T) {
	e := engine.New()
	d := NewDNSSpoofer(e)

	d.mu.RLock()
	_, exists := d.hosts["nonexistent.com"]
	d.mu.RUnlock()

	if exists {
		t.Error("non-existent host should not be found")
	}
}

// Helper: build a minimal DNS A-record query
func buildDNSQuery(domain string) []byte {
	// Transaction ID
	query := []byte{0x00, 0x01}
	// Flags: standard query
	query = append(query, 0x01, 0x00)
	// Questions: 1
	query = append(query, 0x00, 0x01)
	// Answer, Authority, Additional: 0
	query = append(query, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// Encode domain name
	parts := []string{}
	current := ""
	for _, c := range domain {
		if c == '.' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}

	for _, part := range parts {
		query = append(query, byte(len(part)))
		query = append(query, []byte(part)...)
	}
	query = append(query, 0x00) // End of domain

	// Type: A (0x0001)
	query = append(query, 0x00, 0x01)
	// Class: IN (0x0001)
	query = append(query, 0x00, 0x01)

	return query
}
