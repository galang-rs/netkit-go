package engine

import (
	"testing"
)

func TestNewFilter_CachesTokens(t *testing.T) {
	f := NewFilter("proto tcp port 80")
	if len(f.tokens) != 4 {
		t.Errorf("Expected 4 cached tokens, got %d", len(f.tokens))
	}
	if f.tokens[0] != "proto" || f.tokens[1] != "tcp" || f.tokens[2] != "port" || f.tokens[3] != "80" {
		t.Errorf("Unexpected tokens: %v", f.tokens)
	}
}

func TestNewFilter_EmptyExpression(t *testing.T) {
	f := NewFilter("")
	if len(f.tokens) != 0 {
		t.Errorf("Empty expression should have 0 tokens, got %d", len(f.tokens))
	}
}

func TestFilter_Matches_EmptyFilter(t *testing.T) {
	f := NewFilter("")
	p := &Packet{Protocol: "TCP", Source: "1.1.1.1", Dest: "2.2.2.2"}
	if !f.Matches(p) {
		t.Error("Empty filter should match everything")
	}
}

func TestFilter_Matches_Proto(t *testing.T) {
	f := NewFilter("proto tcp")
	tcp := &Packet{Protocol: "TCP", Source: "1.1.1.1", Dest: "2.2.2.2"}
	udp := &Packet{Protocol: "UDP", Source: "1.1.1.1", Dest: "2.2.2.2"}

	if !f.Matches(tcp) {
		t.Error("proto tcp filter should match TCP packet")
	}
	if f.Matches(udp) {
		t.Error("proto tcp filter should NOT match UDP packet")
	}
}

func TestFilter_Matches_Src(t *testing.T) {
	f := NewFilter("src 10.0.0")
	p1 := &Packet{Protocol: "TCP", Source: "10.0.0.1", Dest: "2.2.2.2"}
	p2 := &Packet{Protocol: "TCP", Source: "192.168.1.1", Dest: "2.2.2.2"}

	if !f.Matches(p1) {
		t.Error("src 10.0.0 should match source 10.0.0.1")
	}
	if f.Matches(p2) {
		t.Error("src 10.0.0 should NOT match source 192.168.1.1")
	}
}

func TestFilter_Matches_Dst(t *testing.T) {
	f := NewFilter("dst 8.8.8.8")
	p1 := &Packet{Protocol: "TCP", Source: "1.1.1.1", Dest: "8.8.8.8"}
	p2 := &Packet{Protocol: "TCP", Source: "1.1.1.1", Dest: "9.9.9.9"}

	if !f.Matches(p1) {
		t.Error("dst 8.8.8.8 should match dest 8.8.8.8")
	}
	if f.Matches(p2) {
		t.Error("dst 8.8.8.8 should NOT match dest 9.9.9.9")
	}
}

func TestFilter_Matches_Port(t *testing.T) {
	f := NewFilter("port 443")
	p1 := &Packet{Protocol: "TCP", SourcePort: 443, DestPort: 80}
	p2 := &Packet{Protocol: "TCP", SourcePort: 80, DestPort: 443}
	p3 := &Packet{Protocol: "TCP", SourcePort: 80, DestPort: 8080}

	if !f.Matches(p1) {
		t.Error("port 443 should match when SourcePort is 443")
	}
	if !f.Matches(p2) {
		t.Error("port 443 should match when DestPort is 443")
	}
	if f.Matches(p3) {
		t.Error("port 443 should NOT match when neither port is 443")
	}
}

func TestFilter_Matches_PortRange(t *testing.T) {
	f := NewFilter("portrange 80-443")
	p1 := &Packet{Protocol: "TCP", SourcePort: 200, DestPort: 1000}
	p2 := &Packet{Protocol: "TCP", SourcePort: 8000, DestPort: 9000}

	if !f.Matches(p1) {
		t.Error("portrange 80-443 should match when SourcePort 200 is in range")
	}
	if f.Matches(p2) {
		t.Error("portrange 80-443 should NOT match when no port is in range")
	}
}

func TestFilter_Matches_Combined(t *testing.T) {
	f := NewFilter("proto tcp port 443")
	tcp443 := &Packet{Protocol: "TCP", SourcePort: 443, DestPort: 80}
	udp443 := &Packet{Protocol: "UDP", SourcePort: 443, DestPort: 80}
	tcp80 := &Packet{Protocol: "TCP", SourcePort: 80, DestPort: 8080}

	if !f.Matches(tcp443) {
		t.Error("Combined filter should match TCP with port 443")
	}
	if f.Matches(udp443) {
		t.Error("Combined filter should NOT match UDP (proto mismatch)")
	}
	if f.Matches(tcp80) {
		t.Error("Combined filter should NOT match TCP with port 80 (port mismatch)")
	}
}

func TestFilter_Matches_CaseInsensitive(t *testing.T) {
	f := NewFilter("proto TCP")
	p := &Packet{Protocol: "tcp"}
	if !f.Matches(p) {
		t.Error("Filter should be case-insensitive")
	}
}

// --- Benchmarks ---

func BenchmarkFilter_Matches_Simple(b *testing.B) {
	f := NewFilter("proto tcp")
	p := &Packet{Protocol: "TCP", Source: "1.1.1.1", Dest: "2.2.2.2"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Matches(p)
	}
}

func BenchmarkFilter_Matches_Complex(b *testing.B) {
	f := NewFilter("proto tcp src 10.0 port 443")
	p := &Packet{Protocol: "TCP", Source: "10.0.0.1", Dest: "2.2.2.2", SourcePort: 443}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Matches(p)
	}
}

func BenchmarkNewFilter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewFilter("proto tcp src 10.0 port 443 portrange 1024-65535")
	}
}
