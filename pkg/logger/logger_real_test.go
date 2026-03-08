package logger

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoggerReal_Global(t *testing.T) {
	// Store original output to restore later
	original := Output
	defer func() { Output = original }()

	var buf bytes.Buffer
	Output = &buf

	Infof("Test Info: %s", "hello")
	_ = Errorf("Test Error: %s", "fail")

	s := buf.String()
	if !strings.Contains(s, "Test Info: hello") {
		t.Errorf("Infof failed, output: %q", s)
	}
	if !strings.Contains(s, "Test Error: fail") {
		t.Errorf("Errorf failed, output: %q", s)
	}
	t.Logf("Logger verified! Content: %q", s)
}
