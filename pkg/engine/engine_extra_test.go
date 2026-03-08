package engine

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/bacot120211/netkit-go/pkg/logger"
)

// --- GetIPType ---

func TestGetIPType_Localhost(t *testing.T) {
	result := GetIPType("127.0.0.1")
	if result != "localhost" {
		t.Errorf("Expected 'localhost', got '%s'", result)
	}
}

func TestGetIPType_IPv6Loopback(t *testing.T) {
	result := GetIPType("::1")
	if result != "localhost" {
		t.Errorf("Expected 'localhost', got '%s'", result)
	}
}

func TestGetIPType_Private_192(t *testing.T) {
	result := GetIPType("192.168.1.1")
	if result != "private" {
		t.Errorf("Expected 'private', got '%s'", result)
	}
}

func TestGetIPType_Private_10(t *testing.T) {
	result := GetIPType("10.0.0.1")
	if result != "private" {
		t.Errorf("Expected 'private', got '%s'", result)
	}
}

func TestGetIPType_Private_172(t *testing.T) {
	result := GetIPType("172.16.0.1")
	if result != "private" {
		t.Errorf("Expected 'private', got '%s'", result)
	}
}

func TestGetIPType_Public(t *testing.T) {
	result := GetIPType("8.8.8.8")
	if result != "public" {
		t.Errorf("Expected 'public', got '%s'", result)
	}
}

func TestGetIPType_Public_CloudFlare(t *testing.T) {
	result := GetIPType("1.1.1.1")
	if result != "public" {
		t.Errorf("Expected 'public', got '%s'", result)
	}
}

func TestGetIPType_Invalid(t *testing.T) {
	result := GetIPType("not-an-ip")
	if result != "unknown" {
		t.Errorf("Expected 'unknown', got '%s'", result)
	}
}

func TestGetIPType_Empty(t *testing.T) {
	result := GetIPType("")
	if result != "unknown" {
		t.Errorf("Expected 'unknown', got '%s'", result)
	}
}

// --- Hexdump ---

func TestHexdump_Basic(t *testing.T) {
	data := []byte("Hello, World!")
	result := Hexdump(data)
	if result == "" {
		t.Error("Hexdump should return non-empty string for non-empty input")
	}
	// Should contain hex representation of 'H' (48)
	if !strings.Contains(result, "48") {
		t.Error("Hexdump should contain hex '48' for 'H'")
	}
}

func TestHexdump_Empty(t *testing.T) {
	result := Hexdump([]byte{})
	if result != "" {
		t.Errorf("Hexdump of empty slice should be empty, got '%s'", result)
	}
}

func TestHexdump_SingleByte(t *testing.T) {
	result := Hexdump([]byte{0xFF})
	if !strings.Contains(result, "ff") {
		t.Errorf("Hexdump should contain 'ff', got '%s'", result)
	}
}

func TestHexdump_NilInput(t *testing.T) {
	result := Hexdump(nil)
	if result != "" {
		t.Errorf("Hexdump of nil should be empty, got '%s'", result)
	}
}

// --- JSONLogger ---

func TestNewJSONLogger_NotNil(t *testing.T) {
	var buf bytes.Buffer
	l := NewJSONLogger(&buf)
	if l == nil {
		t.Fatal("NewJSONLogger should return non-nil logger")
	}
}

func TestJSONLogger_Info(t *testing.T) {
	var buf bytes.Buffer
	// Set logger output to our buffer
	oldOutput := logger.Output
	logger.Output = &buf
	defer func() { logger.Output = oldOutput }()

	l := NewJSONLogger(&buf)
	l.Info("TestComponent", "test message", nil)
	// Wait for async worker to process
	time.Sleep(50 * time.Millisecond)

	output := buf.String()
	if output == "" {
		t.Fatal("Logger should have written output")
	}

	// Should contain the message and component in colored format
	if !strings.Contains(output, "[TestComponent] test message") {
		t.Errorf("Expected output to contain message, got '%s'", output)
	}
	// Should contain green color code (\033[32m)
	if !strings.Contains(output, "\033[32m") {
		t.Error("Output should contain green color code")
	}
}

func TestJSONLogger_Error(t *testing.T) {
	var buf bytes.Buffer
	oldOutput := logger.Output
	logger.Output = &buf
	defer func() { logger.Output = oldOutput }()

	l := NewJSONLogger(&buf)
	l.Error("ErrorComp", "something failed", nil)
	time.Sleep(50 * time.Millisecond)

	output := buf.String()
	if !strings.Contains(output, "[ErrorComp] something failed") {
		t.Errorf("Expected output to contain error message, got '%s'", output)
	}
	// Should contain red color code (\033[31m)
	if !strings.Contains(output, "\033[31m") {
		t.Error("Output should contain red color code")
	}
}

func TestJSONLogger_WithData(t *testing.T) {
	var buf bytes.Buffer
	oldOutput := logger.Output
	logger.Output = &buf
	defer func() { logger.Output = oldOutput }()

	l := NewJSONLogger(&buf)
	data := map[string]interface{}{"key": "value", "count": float64(42)}
	l.Info("DataComp", "with data", data)
	time.Sleep(50 * time.Millisecond)

	output := buf.String()
	// Data is currently ignored in the new human-readable logger per implementation in pkg/engine/logger.go
	if !strings.Contains(output, "[DataComp] with data") {
		t.Errorf("Expected output to contain message, got '%s'", output)
	}
}

func TestJSONLogger_Simple(t *testing.T) {
	var buf bytes.Buffer
	oldOutput := logger.Output
	logger.Output = &buf
	defer func() { logger.Output = oldOutput }()

	l := NewJSONLogger(&buf)
	l.Log("WARN", "WarnComp", "warning message", nil)
	time.Sleep(50 * time.Millisecond)

	output := buf.String()
	if !strings.Contains(output, "[WarnComp] warning message") {
		t.Errorf("Expected output to contain warning, got '%s'", output)
	}
	// Should contain yellow color code (\033[33m)
	if !strings.Contains(output, "\033[33m") {
		t.Error("Output should contain yellow color code")
	}
}
