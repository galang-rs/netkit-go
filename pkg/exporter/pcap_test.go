package exporter

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// --- NewPCAPWriter ---

func TestNewPCAPWriter_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter failed: %v", err)
	}
	defer pw.Close()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("PCAP file should exist after creation")
	}
}

func TestNewPCAPWriter_InvalidPath(t *testing.T) {
	_, err := NewPCAPWriter("/nonexistent/dir/test.pcap")
	if err == nil {
		t.Error("NewPCAPWriter should fail with invalid path")
	}
}

// --- PCAP Global Header ---

func TestPCAPWriter_GlobalHeader_MagicNumber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "magic.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter failed: %v", err)
	}
	pw.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read PCAP file: %v", err)
	}

	if len(data) < 24 {
		t.Fatalf("PCAP file too short: %d bytes (expected at least 24)", len(data))
	}

	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != 0xa1b2c3d4 {
		t.Errorf("Expected PCAP magic 0xa1b2c3d4, got 0x%08x", magic)
	}
}

func TestPCAPWriter_GlobalHeader_Version(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "version.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter failed: %v", err)
	}
	pw.Close()

	data, _ := os.ReadFile(path)
	majorVer := binary.LittleEndian.Uint16(data[4:6])
	minorVer := binary.LittleEndian.Uint16(data[6:8])

	if majorVer != 2 {
		t.Errorf("Expected PCAP major version 2, got %d", majorVer)
	}
	if minorVer != 4 {
		t.Errorf("Expected PCAP minor version 4, got %d", minorVer)
	}
}

func TestPCAPWriter_GlobalHeader_SnapLen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snaplen.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter failed: %v", err)
	}
	pw.Close()

	data, _ := os.ReadFile(path)
	snapLen := binary.LittleEndian.Uint32(data[16:20])

	if snapLen != 65535 {
		t.Errorf("Expected snap length 65535, got %d", snapLen)
	}
}

func TestPCAPWriter_GlobalHeader_LinkType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "linktype.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter failed: %v", err)
	}
	pw.Close()

	data, _ := os.ReadFile(path)
	linkType := binary.LittleEndian.Uint32(data[20:24])

	if linkType != 1 {
		t.Errorf("Expected link type 1 (Ethernet), got %d", linkType)
	}
}

// --- WritePacket ---

func TestPCAPWriter_WritePacket_GrowsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "packets.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter failed: %v", err)
	}

	// Get size after global header
	pw.Close()
	info1, _ := os.Stat(path)
	headerSize := info1.Size()

	// Reopen and write a packet
	pw2, _ := NewPCAPWriter(path)
	payload := []byte("Hello, PCAP!")
	if err := pw2.WritePacket(payload); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}
	pw2.Close()

	info2, _ := os.Stat(path)
	// Should be header (24) + packet header (16) + payload (12) = 52
	if info2.Size() <= headerSize {
		t.Errorf("File should grow after WritePacket: headerOnly=%d, withPacket=%d", headerSize, info2.Size())
	}
}

func TestPCAPWriter_WritePacket_PacketHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pktheader.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter failed: %v", err)
	}

	payload := []byte("TestPayload123")
	pw.WritePacket(payload)
	pw.Close()

	data, _ := os.ReadFile(path)
	// Packet header starts at byte 24 (after global header)
	if len(data) < 24+16 {
		t.Fatal("File too short — missing packet header")
	}

	// Bytes 32-36: captured length, bytes 36-40: original length
	capturedLen := binary.LittleEndian.Uint32(data[32:36])
	originalLen := binary.LittleEndian.Uint32(data[36:40])

	if capturedLen != uint32(len(payload)) {
		t.Errorf("Expected captured length %d, got %d", len(payload), capturedLen)
	}
	if originalLen != uint32(len(payload)) {
		t.Errorf("Expected original length %d, got %d", len(payload), originalLen)
	}
}

func TestPCAPWriter_WritePacket_MultiplePackets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter failed: %v", err)
	}

	for i := 0; i < 5; i++ {
		if err := pw.WritePacket([]byte("packet")); err != nil {
			t.Fatalf("WritePacket #%d failed: %v", i, err)
		}
	}
	pw.Close()

	data, _ := os.ReadFile(path)
	// 24 (global header) + 5 * (16 + 6) = 24 + 110 = 134
	expectedSize := int64(24 + 5*(16+6))
	if int64(len(data)) != expectedSize {
		t.Errorf("Expected file size %d, got %d", expectedSize, len(data))
	}
}

// --- Close ---

func TestPCAPWriter_Close(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "close.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter failed: %v", err)
	}

	if err := pw.Close(); err != nil {
		t.Errorf("Close should not return error: %v", err)
	}
}

func TestPCAPWriter_WritePacket_EmptyPayload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pcap")

	pw, err := NewPCAPWriter(path)
	if err != nil {
		t.Fatalf("NewPCAPWriter failed: %v", err)
	}

	// Writing empty payload should not error
	if err := pw.WritePacket([]byte{}); err != nil {
		t.Errorf("WritePacket with empty payload should not error: %v", err)
	}
	pw.Close()
}

func TestPCAPWriter_RotationSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rotate_size.pcap")

	pw, _ := NewPCAPWriter(path)
	pw.SetRotation(100, 0) // Rotate after 100 bytes

	// Initial file should exist
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}

	// Write enough to trigger rotation
	payload := make([]byte, 60)
	_ = pw.WritePacket(payload) // 24 + 16 + 60 = 100 bytes
	_ = pw.WritePacket(payload) // triggers rotation before write since 100 >= 100
	_ = pw.WritePacket(payload) // just to be sure

	pw.Close()

	// Check that a rotated file exists
	matches, _ := filepath.Glob(filepath.Join(dir, "rotate_size_*"))
	if len(matches) == 0 {
		t.Error("No rotated files found")
	}
}

func TestPCAPWriter_Compression(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compressed.pcap")

	pw, _ := NewPCAPWriter(path)
	pw.SetCompression(true)
	pw.SetRotation(10, 0) // Force rotation on next write
	_ = pw.WritePacket([]byte("test"))
	pw.Close()

	matches, _ := filepath.Glob(filepath.Join(dir, "compressed_*"))
	foundGz := false
	for _, m := range matches {
		if filepath.Ext(m) == ".gz" {
			foundGz = true
			break
		}
	}
	if !foundGz {
		t.Error("No compressed files found")
	}
}

func TestPCAPWriter_Filter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "filter.pcap")

	pw, _ := NewPCAPWriter(path)
	pw.SetFilter(func(data []byte) bool {
		return string(data) == "keep"
	})

	_ = pw.WritePacket([]byte("keep"))
	_ = pw.WritePacket([]byte("discard"))
	pw.Close()

	// 24 (header) + 1 * (16 + 4) = 44
	info, _ := os.Stat(path)
	if info.Size() != 44 {
		t.Errorf("Expected file size 44, got %d", info.Size())
	}
}
