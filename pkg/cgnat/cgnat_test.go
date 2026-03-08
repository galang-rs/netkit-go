package cgnat

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// --- STUN ---

func TestBuildSTUNRequest_Basic(t *testing.T) {
	txID := make([]byte, 12)
	for i := range txID {
		txID[i] = byte(i)
	}

	msg := buildSTUNRequest(txID, 0)

	if len(msg) != 20 {
		t.Errorf("Expected 20 bytes, got %d", len(msg))
	}
	if binary.BigEndian.Uint16(msg[0:2]) != stunBindingRequest {
		t.Error("Wrong message type")
	}
	if binary.BigEndian.Uint16(msg[2:4]) != 0 {
		t.Error("Expected 0 attributes length")
	}
	if binary.BigEndian.Uint32(msg[4:8]) != magicCookie {
		t.Error("Wrong magic cookie")
	}
	if !bytes.Equal(msg[8:20], txID) {
		t.Error("Transaction ID mismatch")
	}
}

func TestBuildSTUNRequest_WithChangeRequest(t *testing.T) {
	txID := make([]byte, 12)
	msg := buildSTUNRequest(txID, changeIP|changePort)

	if len(msg) != 28 {
		t.Errorf("Expected 28 bytes (20 header + 8 attr), got %d", len(msg))
	}
	if binary.BigEndian.Uint16(msg[2:4]) != 8 {
		t.Error("Expected 8 bytes attributes length")
	}
	if binary.BigEndian.Uint16(msg[20:22]) != attrChangeRequest {
		t.Error("Expected CHANGE-REQUEST attribute")
	}
	if msg[27] != changeIP|changePort {
		t.Errorf("Expected change flags 0x%02x, got 0x%02x", changeIP|changePort, msg[27])
	}
}

func TestParseMappedAddress_IPv4(t *testing.T) {
	// Family=1 (IPv4), Port=1234, IP=192.168.1.100
	data := []byte{0x00, 0x01, 0x04, 0xD2, 192, 168, 1, 100}
	addr := parseMappedAddress(data)
	if addr == nil {
		t.Fatal("Expected non-nil address")
	}
	if addr.Port != 1234 {
		t.Errorf("Expected port 1234, got %d", addr.Port)
	}
	if !addr.IP.Equal(net.IPv4(192, 168, 1, 100)) {
		t.Errorf("Expected 192.168.1.100, got %s", addr.IP)
	}
}

func TestParseMappedAddress_TooShort(t *testing.T) {
	addr := parseMappedAddress([]byte{0x00, 0x01})
	if addr != nil {
		t.Error("Expected nil for short data")
	}
}

func TestParseMappedAddress_IPv6(t *testing.T) {
	// Family=2 (IPv6), Port=1234, IP=2001:db8::1
	ip := net.ParseIP("2001:db8::1")
	data := make([]byte, 20)
	data[1] = 0x02
	binary.BigEndian.PutUint16(data[2:4], 1234)
	copy(data[4:], ip)

	addr := parseMappedAddress(data)
	if addr == nil {
		t.Fatal("Expected non-nil address")
	}
	if addr.Port != 1234 {
		t.Errorf("Expected port 1234, got %d", addr.Port)
	}
	if !addr.IP.Equal(ip) {
		t.Errorf("Expected %s, got %s", ip, addr.IP)
	}
}

func TestParseXORMappedAddress(t *testing.T) {
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, magicCookie)
	txID := make([]byte, 12)

	// XOR the expected values with the cookie
	expectedPort := uint16(8080)
	expectedIP := net.IPv4(203, 0, 113, 1).To4()

	xPort := expectedPort ^ uint16(magicCookie>>16)
	xIP := binary.BigEndian.Uint32(expectedIP) ^ magicCookie

	data := make([]byte, 8)
	data[0] = 0x00
	data[1] = 0x01 // IPv4
	binary.BigEndian.PutUint16(data[2:4], xPort)
	binary.BigEndian.PutUint32(data[4:8], xIP)

	addr := parseXORMappedAddress(data, cookie, txID)
	if addr == nil {
		t.Fatal("Expected non-nil address")
	}
	if addr.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", addr.Port)
	}
	if !addr.IP.Equal(net.IPv4(203, 0, 113, 1)) {
		t.Errorf("Expected 203.0.113.1, got %s", addr.IP)
	}
}

func TestParseXORMappedAddress_IPv6(t *testing.T) {
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, magicCookie)
	txID := make([]byte, 12)
	for i := range txID {
		txID[i] = byte(i)
	}

	expectedPort := uint16(8080)
	expectedIP := net.ParseIP("2001:db8::1")

	xPort := expectedPort ^ uint16(magicCookie>>16)
	xor := append(cookie, txID...)
	xIP := make([]byte, 16)
	for i := 0; i < 16; i++ {
		xIP[i] = expectedIP[i] ^ xor[i]
	}

	data := make([]byte, 20)
	data[1] = 0x02 // IPv6
	binary.BigEndian.PutUint16(data[2:4], xPort)
	copy(data[4:], xIP)

	addr := parseXORMappedAddress(data, cookie, txID)
	if addr == nil {
		t.Fatal("Expected non-nil address")
	}
	if addr.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", addr.Port)
	}
	if !addr.IP.Equal(expectedIP) {
		t.Errorf("Expected %s, got %s", expectedIP, addr.IP)
	}
}

func TestParseSTUNResponse_Valid(t *testing.T) {
	txID := make([]byte, 12)
	for i := range txID {
		txID[i] = byte(i + 1)
	}

	// Build a minimal valid response with MAPPED-ADDRESS
	mappedData := []byte{0x00, 0x01, 0x1F, 0x90, 8, 8, 8, 8} // Port 8080, IP 8.8.8.8
	attrLen := 4 + len(mappedData)                           // attr header + attr data

	resp := make([]byte, 20+attrLen)
	binary.BigEndian.PutUint16(resp[0:2], stunBindingResponse)
	binary.BigEndian.PutUint16(resp[2:4], uint16(attrLen))
	binary.BigEndian.PutUint32(resp[4:8], magicCookie)
	copy(resp[8:20], txID)

	// MAPPED-ADDRESS attribute
	binary.BigEndian.PutUint16(resp[20:22], attrMappedAddress)
	binary.BigEndian.PutUint16(resp[22:24], uint16(len(mappedData)))
	copy(resp[24:], mappedData)

	result, err := parseSTUNResponse(resp, txID)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if result.MappedAddr == nil {
		t.Fatal("MappedAddr should not be nil")
	}
	if result.MappedAddr.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", result.MappedAddr.Port)
	}
	if !result.MappedAddr.IP.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Errorf("Expected 8.8.8.8, got %s", result.MappedAddr.IP)
	}
}

func TestParseSTUNResponse_TxIDMismatch(t *testing.T) {
	resp := make([]byte, 20)
	binary.BigEndian.PutUint16(resp[0:2], stunBindingResponse)
	binary.BigEndian.PutUint32(resp[4:8], magicCookie)

	txID := make([]byte, 12)
	txID[0] = 0xFF // Different from zeros in resp

	_, err := parseSTUNResponse(resp, txID)
	if err == nil {
		t.Error("Expected error for transaction ID mismatch")
	}
}

func TestParseSTUNResponse_ErrorResponse(t *testing.T) {
	resp := make([]byte, 20)
	binary.BigEndian.PutUint16(resp[0:2], stunBindingError)
	binary.BigEndian.PutUint32(resp[4:8], magicCookie)

	_, err := parseSTUNResponse(resp, make([]byte, 12))
	if err == nil {
		t.Error("Expected error for error response")
	}
}

func TestParseSTUNResponse_TooShort(t *testing.T) {
	_, err := parseSTUNResponse([]byte{0x01}, make([]byte, 12))
	if err == nil {
		t.Error("Expected error for short response")
	}
}

// --- NAT Type ---

func TestNATType_String(t *testing.T) {
	tests := []struct {
		nat      NATType
		expected string
	}{
		{NATNone, "No NAT (Direct)"},
		{NATFullCone, "Full Cone NAT"},
		{NATRestrictedCone, "Restricted Cone NAT"},
		{NATPortRestrictedCone, "Port-Restricted Cone NAT"},
		{NATSymmetric, "Symmetric NAT"},
		{NATBlocked, "UDP Blocked"},
		{NATUnknown, "Unknown"},
	}
	for _, tt := range tests {
		if tt.nat.String() != tt.expected {
			t.Errorf("NATType(%d).String() = %s, want %s", tt.nat, tt.nat.String(), tt.expected)
		}
	}
}

func TestNATType_CanHolePunch(t *testing.T) {
	tests := []struct {
		nat    NATType
		expect bool
	}{
		{NATNone, true},
		{NATFullCone, true},
		{NATRestrictedCone, true},
		{NATPortRestrictedCone, true},
		{NATSymmetric, false},
		{NATBlocked, false},
	}
	for _, tt := range tests {
		if tt.nat.CanHolePunch() != tt.expect {
			t.Errorf("NATType(%s).CanHolePunch() = %v, want %v", tt.nat, tt.nat.CanHolePunch(), tt.expect)
		}
	}
}

// --- Network Type ---

func TestNetworkType_String(t *testing.T) {
	if NetworkMobile.String() != "Mobile" {
		t.Error("Mobile string mismatch")
	}
	if NetworkWiFi.String() != "WiFi" {
		t.Error("WiFi string mismatch")
	}
	if NetworkEthernet.String() != "Ethernet" {
		t.Error("Ethernet string mismatch")
	}
}

func TestNetworkType_KeepAliveInterval(t *testing.T) {
	if NetworkMobile.KeepAliveInterval() != 15*time.Second {
		t.Error("Mobile keepalive should be 15s")
	}
	if NetworkWiFi.KeepAliveInterval() != 25*time.Second {
		t.Error("WiFi keepalive should be 25s")
	}
	if NetworkEthernet.KeepAliveInterval() != 30*time.Second {
		t.Error("Ethernet keepalive should be 30s")
	}
}

// --- ISP Detection ---

func TestDetectISP_CGNAT(t *testing.T) {
	isp := detectISP(net.IPv4(100, 64, 0, 1))
	if isp != ISPCGNAT {
		t.Errorf("Expected ISPCGNAT, got %s", isp)
	}

	isp2 := detectISP(net.IPv4(100, 127, 255, 254))
	if isp2 != ISPCGNAT {
		t.Errorf("Expected ISPCGNAT, got %s", isp2)
	}
}

func TestDetectISP_Private(t *testing.T) {
	isp := detectISP(net.IPv4(10, 0, 0, 1))
	if isp != ISPPrivate {
		t.Errorf("Expected ISPPrivate, got %s", isp)
	}
}

func TestDetectISP_Nil(t *testing.T) {
	isp := detectISP(nil)
	if isp != ISPUnknown {
		t.Errorf("Expected ISPUnknown, got %s", isp)
	}
}

// --- Detector ---

func TestNewDetector(t *testing.T) {
	d := NewDetector()
	if d == nil {
		t.Fatal("Detector should not be nil")
	}
	if len(d.stunServers) == 0 {
		t.Error("Should have default STUN servers")
	}
}

func TestNewDetectorWithServers(t *testing.T) {
	servers := []string{"stun.test.com:3478"}
	d := NewDetectorWithServers(servers)
	if len(d.stunServers) != 1 || d.stunServers[0] != "stun.test.com:3478" {
		t.Error("Custom servers not set")
	}
}

func TestListInterfaces(t *testing.T) {
	ifaces := ListInterfaces()
	// Should return at least info (may be empty in CI, but shouldn't panic)
	t.Logf("Found %d interfaces", len(ifaces))
	for _, iface := range ifaces {
		t.Logf("  %s: type=%s ipv4=%s mtu=%d", iface.Name, iface.Type, iface.IPv4, iface.MTU)
	}
}

// --- HolePunch ---

func TestHolePunchState_String(t *testing.T) {
	if HolePunchIdle.String() != "Idle" {
		t.Error("Idle string mismatch")
	}
	if HolePunchPunching.String() != "Punching" {
		t.Error("Punching string mismatch")
	}
	if HolePunchConnected.String() != "Connected" {
		t.Error("Connected string mismatch")
	}
	if HolePunchFailed.String() != "Failed" {
		t.Error("Failed string mismatch")
	}
}

func TestDefaultHolePunchConfig(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5000}
	cfg := DefaultHolePunchConfig(peer)
	if cfg.PeerAddr != peer {
		t.Error("PeerAddr mismatch")
	}
	if cfg.Timeout != 10*time.Second {
		t.Error("Default timeout should be 10s")
	}
	if cfg.MaxRetries != 100 {
		t.Error("Default retries should be 100")
	}
}

func TestHolePuncher_State(t *testing.T) {
	hp := NewHolePuncher()
	if hp.State() != HolePunchIdle {
		t.Error("Initial state should be Idle")
	}
}

func TestHolePuncher_Close_NilConn(t *testing.T) {
	hp := NewHolePuncher()
	err := hp.Close()
	if err != nil {
		t.Errorf("Close nil conn should not error: %v", err)
	}
}

// --- Bypass Strategy ---

func TestBypassStrategy_String(t *testing.T) {
	tests := []struct {
		s    BypassStrategy
		want string
	}{
		{StrategyDirect, "Direct (No NAT)"},
		{StrategyUPnP, "UPnP Port Mapping"},
		{StrategyNATPMP, "NAT-PMP Port Mapping"},
		{StrategyHolePunch, "UDP Hole-Punch"},
		{StrategyRelay, "Encrypted Relay"},
		{StrategyNone, "None"},
	}
	for _, tt := range tests {
		if tt.s.String() != tt.want {
			t.Errorf("Strategy(%d).String() = %s, want %s", tt.s, tt.s.String(), tt.want)
		}
	}
}

// --- Bypass Orchestrator ---

func TestNewBypass(t *testing.T) {
	b := NewBypass()
	if b == nil {
		t.Fatal("Bypass should not be nil")
	}
	if b.detector == nil {
		t.Error("Detector should be initialized")
	}
	if b.puncher == nil {
		t.Error("Puncher should be initialized")
	}
}

func TestBypass_SetRelay(t *testing.T) {
	b := NewBypass()
	key := make([]byte, 32)
	b.SetRelay("relay.example.com:8443", "token123", key)
	if b.relayAddr != "relay.example.com:8443" {
		t.Error("Relay addr not set")
	}
	if b.relayToken != "token123" {
		t.Error("Relay token not set")
	}
}

func TestBypass_SetOnDetect(t *testing.T) {
	b := NewBypass()
	b.SetOnDetect(func(r *BypassResult) {})
	if b.onDetect == nil {
		t.Error("OnDetect should be set")
	}
}

func TestBypass_ChooseStrategy(t *testing.T) {
	b := NewBypass()

	tests := []struct {
		natType    NATType
		routerType string
		expected   BypassStrategy
	}{
		{NATNone, "VPS/Direct", StrategyDirect},
		{NATFullCone, "MikroTik", StrategyUPnP},
		{NATFullCone, "Generic", StrategyHolePunch},
		{NATRestrictedCone, "MikroTik", StrategyUPnP},
		{NATPortRestrictedCone, "UPnP Router", StrategyUPnP},
		{NATPortRestrictedCone, "Unknown", StrategyHolePunch},
		{NATSymmetric, "MikroTik", StrategyUPnP},
		{NATSymmetric, "Unknown", StrategyRelay},
		{NATBlocked, "Any", StrategyRelay},
	}

	for _, tt := range tests {
		result := &BypassResult{NATType: tt.natType, RouterType: tt.routerType}
		strategy := b.chooseStrategy(result)
		if strategy != tt.expected {
			t.Errorf("NAT=%s Router=%s: got %s, want %s",
				tt.natType, tt.routerType, strategy, tt.expected)
		}
	}
}

// --- Encryption ---

func TestEncryptDecrypt_ChaCha(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("Hello, CGNAT bypass!")
	encrypted, err := encryptChaCha(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if bytes.Equal(encrypted, plaintext) {
		t.Error("Encrypted should differ from plaintext")
	}

	decrypted, err := decryptChaCha(key, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted mismatch: got %s, want %s", string(decrypted), string(plaintext))
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 0xFF

	encrypted, _ := encryptChaCha(key1, []byte("secret"))
	_, err := decryptChaCha(key2, encrypted)
	if err == nil {
		t.Error("Decrypt with wrong key should fail")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	key := make([]byte, 32)
	_, err := decryptChaCha(key, []byte("short"))
	if err == nil {
		t.Error("Decrypt short ciphertext should fail")
	}
}

// --- MikroTik ---

func TestNewMikroTikBypass(t *testing.T) {
	m := NewMikroTikBypass("192.168.1.1", "admin", "password")
	if m.Host != "192.168.1.1" {
		t.Error("Host mismatch")
	}
	if m.Port != 8728 {
		t.Error("Default port should be 8728")
	}
	if m.Username != "admin" {
		t.Error("Username mismatch")
	}
}

// --- Integration: Auto-Detect (no network dependency) ---

func TestBypass_AutoDetect_ReturnsResult(t *testing.T) {
	b := NewBypass()
	// Use unreachable STUN servers so it falls through quickly
	b.detector = NewDetectorWithServers([]string{"192.0.2.1:3478"}) // TEST-NET
	b.detector.stun.Timeout = 500 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result := b.AutoDetect(ctx)
	if result == nil {
		t.Fatal("AutoDetect should always return a result")
	}

	// With unreachable STUN, NAT type should be Blocked or Unknown
	t.Logf("NAT: %s, Network: %s, ISP: %s, Router: %s, Strategy: %s",
		result.NATType, result.NetworkType, result.ISP, result.RouterType, result.Strategy)
}

// --- Benchmarks ---

func BenchmarkBuildSTUNRequest(b *testing.B) {
	txID := make([]byte, 12)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildSTUNRequest(txID, 0)
	}
}

func BenchmarkParseMappedAddress(b *testing.B) {
	data := []byte{0x00, 0x01, 0x04, 0xD2, 192, 168, 1, 100}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseMappedAddress(data)
	}
}

func BenchmarkDetectISP(b *testing.B) {
	ip := net.IPv4(100, 64, 0, 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detectISP(ip)
	}
}

func BenchmarkEncryptChaCha(b *testing.B) {
	key := make([]byte, 32)
	data := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptChaCha(key, data)
	}
}
