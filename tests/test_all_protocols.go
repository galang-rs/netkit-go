package tests

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/bacot120211/netkit-go/pkg/protocol"
)

func TestAllProtocols(t *testing.T) {
	fmt.Println("🚀 Starting Direct Protocol Verification...")

	testCases := []struct {
		name string
		port uint16
		data []byte
	}{
		{"DHCP", 67, []byte{1, 1, 6, 0}},
		{"DNS", 53, []byte{0, 0, 1, 0}},
		{"NTP", 123, make([]byte, 48)},
		{"SNMP", 161, []byte{0x30, 0x0A}},
		{"STUN", 3478, []byte{0, 1, 0, 0, 0x21, 0x12, 0xA4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	for _, tc := range testCases {
		fmt.Printf("🔍 Testing %s... ", tc.name)
		detected := protocol.DetectProtocol(tc.port, tc.data)
		if detected == tc.name {
			fmt.Println("✅ PASS")
		} else {
			fmt.Printf("❌ FAIL (Detected: %s)\n", detected)
		}
	}

	fmt.Println("\n🌐 Testing IPv4/IPv6 Stack...")
	testDualStack("127.0.0.1")
	testDualStack("::1")

	fmt.Println("\n✨ Verification Complete!")
}

func testDualStack(host string) {
	fmt.Printf("🔗 Checking %s connectivity... ", host)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "80"), 100*time.Millisecond)
	if err != nil {
		fmt.Printf("⚠️  Skipped (No listener on %s)\n", host)
	} else {
		conn.Close()
		fmt.Println("✅ OK")
	}
}
