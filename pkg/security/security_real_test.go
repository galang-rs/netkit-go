package security

import (
	"testing"
	"time"
)

func TestSecurityReal_ProductFlow(t *testing.T) {
	// 1. Test Bruteforce Limiter (Real product behavior)
	t.Run("BruteforceLimiter", func(t *testing.T) {
		bl := NewBruteforceLimiter(3, 1*time.Minute, 1*time.Minute)
		testIP := "10.0.0.5"

		// Should be allowed initially
		if !bl.IsAllowed(testIP) {
			t.Errorf("IP %s should be allowed initially", testIP)
		}

		// Record 2 failures
		bl.RecordFailure(testIP)
		bl.RecordFailure(testIP)
		if !bl.IsAllowed(testIP) {
			t.Errorf("IP %s should still be allowed after 2 failures", testIP)
		}

		// 3rd failure should ban
		isBanned := bl.RecordFailure(testIP)
		if !isBanned {
			t.Errorf("RecordFailure should return true for 3rd failure")
		}
		if bl.IsAllowed(testIP) {
			t.Errorf("IP %s should be banned after 3 failures", testIP)
		}

		// Verify it's in the banned list
		banned := bl.GetBannedIPs()
		found := false
		for _, ip := range banned {
			if ip == testIP {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("IP %s not found in banned list", testIP)
		}

		// Manual unban
		bl.UnbanIP(testIP)
		if !bl.IsAllowed(testIP) {
			t.Errorf("IP %s should be allowed after manual unban", testIP)
		}
	})

	// 2. Test Scope Management (Guard functionality)
	t.Run("ScopeManager", func(t *testing.T) {
		sm := NewScopeManager(RoleBoth) // Default role

		// Registered features check
		if err := sm.Guard("capture"); err != nil {
			t.Errorf("RoleBoth should be allowed to use 'capture': %v", err)
		}

		// Switch to ClientOnly role simulation
		sm.SetRole(RoleClient)
		if err := sm.Guard("capture"); err != nil {
			t.Errorf("RoleClient should be allowed to use 'capture': %v", err)
		}
		if err := sm.Guard("tunnel_server"); err == nil {
			t.Errorf("RoleClient should NOT be allowed to use 'tunnel_server'")
		}

		// Switch to ServerOnly role
		sm.SetRole(RoleServer)
		if err := sm.Guard("tunnel_server"); err != nil {
			t.Errorf("RoleServer should be allowed to use 'tunnel_server': %v", err)
		}
		// 'capture' is FeatureScopeClientOnly
		if err := sm.Guard("capture"); err == nil {
			t.Errorf("RoleServer should NOT be allowed to use 'capture'")
		}

		// Verify violation log contains the 'capture' block
		violations := sm.GetViolations()
		found := false
		for _, v := range violations {
			if v.Feature == "capture" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected violation for 'capture' not found in log")
		}
	})

	// 3. Test Firewall Rules
	t.Run("Firewall", func(t *testing.T) {
		fw := NewFirewall()

		// Add a block rule for a specific IP
		fw.AddRule(FirewallRule{
			Name:     "BlockBadActor",
			Action:   FirewallDeny,
			SrcIP:    "192.168.1.100",
			Priority: 10,
			Enabled:  true,
		})

		// Add a higher priority allow rule for the same IP on a specific port
		fw.AddRule(FirewallRule{
			Name:     "AllowSSH",
			Action:   FirewallAllow,
			SrcIP:    "192.168.1.100",
			DstPort:  22,
			Priority: 5,
			Enabled:  true,
		})

		// Case 1: IP 192.168.1.100 on random port -> Should DENY
		if act := fw.Evaluate("192.168.1.100", 12345, "1.1.1.1", 80, "tcp", DirectionInbound); act != FirewallDeny {
			t.Errorf("Expected DENY for bad actor, got %v", act)
		}

		// Case 2: IP 192.168.1.100 on port 22 -> Should ALLOW (higher priority)
		if act := fw.Evaluate("192.168.1.100", 12345, "1.1.1.1", 22, "tcp", DirectionInbound); act != FirewallAllow {
			t.Errorf("Expected ALLOW for SSH, got %v", act)
		}

		// Case 3: Other IP -> Should ALLOW (default)
		if act := fw.Evaluate("8.8.8.8", 12345, "1.1.1.1", 80, "tcp", DirectionInbound); act != FirewallAllow {
			t.Errorf("Expected default ALLOW for other IPs, got %v", act)
		}
	})
}
