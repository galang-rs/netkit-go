package exporter

import (
	"os"
	"testing"
)

func TestExporterReal_PCAP(t *testing.T) {
	tmpFile := t.TempDir() + "/test.pcap"
	w, err := NewPCAPWriter(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create PCAP writer: %v", err)
	}
	defer w.Close()

	// 1. Write dummy packet
	dummy := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	if err := w.WritePacket(dummy); err != nil {
		t.Fatalf("Failed to write packet: %v", err)
	}
	w.Close()

	// 2. Verify file existence and size
	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("PCAP file was not created: %v", err)
	}
	// GlobalHeader(24) + PacketHeader(16) + Payload(6) = 46
	if info.Size() < 46 {
		t.Errorf("PCAP file too small: %d bytes", info.Size())
	}
	t.Logf("PCAP Export verified! File size: %d bytes", info.Size())
}
