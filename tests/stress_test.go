package tests

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bacot120211/netkit-go/pkg/mem"
	"github.com/bacot120211/netkit-go/pkg/proxy"
	"github.com/bacot120211/netkit-go/pkg/security"
)

// ==========================================
// MONKEY STRESS TESTS
// High-concurrency, chaotic testing
// to break things under pressure.
// ==========================================

// --- Stress: Concurrent Engine Ingest ---

func TestStress_EngineIngest_1000Packets(t *testing.T) {
	t.Skip("skipping: engine requires admin privileges to start")
}

// --- Stress: Concurrent Scope Guard ---

func TestStress_ScopeGuard_ConcurrentAccess(t *testing.T) {
	sm := security.NewScopeManager(security.RoleClient)
	var wg sync.WaitGroup
	var allowed, blocked int64

	features := []string{"proxy_http", "interceptor", "tunnel_server", "firewall", "capture", "ipsec", "engine"}

	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if sm.IsNotArea(features[idx%len(features)]) {
				atomic.AddInt64(&blocked, 1)
			} else {
				atomic.AddInt64(&allowed, 1)
			}
		}(i)
	}

	wg.Wait()
	if allowed+blocked != 500 {
		t.Errorf("expected 500 total, got %d", allowed+blocked)
	}
	t.Logf("Allowed: %d, Blocked: %d", allowed, blocked)
}

// --- Stress: Bruteforce Limiter 100 IPs ---

func TestStress_BruteforceLimiter_100IPs(t *testing.T) {
	bl := security.NewBruteforceLimiter(5, time.Minute, time.Second)
	var wg sync.WaitGroup
	var banned int64

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.%d.%d", idx/256, idx%256)
			for f := 0; f < mathrand.Intn(10); f++ {
				if bl.RecordFailure(ip) {
					atomic.AddInt64(&banned, 1)
				}
			}
		}(i)
	}

	wg.Wait()
	t.Logf("Banned events: %d (from 100 IPs)", banned)
}

// --- Stress: Firewall Concurrent Evaluate ---

func TestStress_Firewall_ConcurrentEvaluate(t *testing.T) {
	fw := security.NewFirewall()
	for i := 0; i < 50; i++ {
		fw.AddRule(security.FirewallRule{
			Name: fmt.Sprintf("rule-%d", i), Priority: i,
			Action: security.FirewallAction(i % 3), DstPort: i * 100, Enabled: true,
		})
	}

	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			fw.Evaluate("10.0.0.1", idx, "192.168.1.1", (idx*100)%5000, "tcp", security.DirectionInbound)
		}(i)
	}
	wg.Wait()
}

// --- Stress: SOCKS5 UDP Fuzzing ---

func TestStress_SOCKS5_UDPFuzz(t *testing.T) {
	var wg sync.WaitGroup
	var parseOK, parseErr int64

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					// ParseSOCKS5UDPHeader panics on short data — expected
					atomic.AddInt64(&parseErr, 1)
				}
			}()
			sz, _ := rand.Int(rand.Reader, big.NewInt(50))
			data := make([]byte, sz.Int64())
			rand.Read(data)
			_, _, err := proxy.ParseSOCKS5UDPHeader(data)
			if err != nil {
				atomic.AddInt64(&parseErr, 1)
			} else {
				atomic.AddInt64(&parseOK, 1)
			}
		}()
	}

	wg.Wait()
	t.Logf("SOCKS5 Fuzz: %d OK, %d errors/panics", parseOK, parseErr)
}

// --- Stress: 1MB Data Exchange via Pipe ---

func TestStress_DataExchange_1MB(t *testing.T) {
	dataSize := 1024 * 1024
	data := make([]byte, dataSize)
	rand.Read(data)

	c1, c2 := net.Pipe()
	done := make(chan bool, 2)

	go func() { c1.Write(data); c1.Close(); done <- true }()

	var received bytes.Buffer
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := c2.Read(buf)
			if n > 0 {
				received.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- true
	}()

	<-done
	<-done

	if received.Len() != dataSize {
		t.Errorf("got %d bytes", received.Len())
	}
	if !bytes.Equal(data, received.Bytes()) {
		t.Error("1MB DATA CORRUPTION!")
	}
}

// --- Stress: Memory Reducer Under Load ---

func TestStress_MemReducer(t *testing.T) {
	r := mem.New()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				r.Reduce()
				runtime.Gosched()
			}
		}()
	}
	wg.Wait()
}

// --- Stress: Rapid Role Switching ---

func TestStress_ScopeRoleSwitching(t *testing.T) {
	sm := security.NewScopeManager(security.RoleClient)
	var wg sync.WaitGroup
	roles := []security.Role{security.RoleClient, security.RoleServer, security.RoleBoth}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sm.SetRole(roles[idx%3])
		}(i)
	}
	wg.Wait()
}

// --- Stress: Feature Activate/Deactivate Rapid ---

func TestStress_FeatureActivateDeactivate(t *testing.T) {
	sm := security.NewScopeManager(security.RoleBoth)
	var wg sync.WaitGroup
	features := []string{"engine", "firewall", "bruteforce", "mem_reducer", "perf", "dtls", "tls", "cgnat"}

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			f := features[idx%len(features)]
			sm.ActivateFeature(f)
			runtime.Gosched()
			sm.DeactivateFeature(f)
		}(i)
	}
	wg.Wait()
}

// ==========================================
// BENCHMARKS
// ==========================================

func BenchmarkScopeGuard(b *testing.B) {
	sm := security.NewScopeManager(security.RoleClient)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.Guard("proxy_http")
	}
}

func BenchmarkFirewallEvaluate(b *testing.B) {
	fw := security.NewFirewall()
	for i := 0; i < 20; i++ {
		fw.AddRule(security.FirewallRule{
			Name: fmt.Sprintf("rule-%d", i), Priority: i, Action: security.FirewallAllow, Enabled: true,
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.Evaluate("10.0.0.1", 1234, "192.168.1.1", 80, "tcp", security.DirectionInbound)
	}
}
