package js_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/js"
	"github.com/bacot120211/netkit-go/pkg/protocol/tls"
)

func TestEngineReal_JSInterception(t *testing.T) {
	// 1. Setup a simple JS script
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test_interceptor.js")
	scriptContent := `
function onPacket(ctx) {
    var p = ctx.Packet.Payload;
    if (p && p.length >= 4) {
        if (p[0] == 80 && p[1] == 73 && p[2] == 78 && p[3] == 71) {
            ctx.Modify("PONG-FROM-JS");
        }
    }
}
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0644); err != nil {
		t.Fatalf("Failed to write JS script: %v", err)
	}

	// 2. Initialize Engine, CA and Runtime
	e := engine.New()
	runtime, _ := js.NewRuntime()
	ca, _ := tls.NewCA()

	jsInt, err := js.NewJSInterceptor(runtime, scriptPath, e, ca, nil)
	if err != nil {
		t.Fatalf("Failed to create JS interceptor: %v", err)
	}
	e.RegisterInterceptor(jsInt)

	// 3. Ingest a packet
	p := &engine.Packet{
		ID:         engine.NextPacketID(),
		Timestamp:  time.Now().Unix(),
		Source:     "127.0.0.1",
		SourcePort: 12345,
		Dest:       "1.1.1.1",
		DestPort:   80,
		Protocol:   "tcp",
		Payload:    []byte("PING Request"),
	}

	// 4. Run process (synchronous)
	action := e.Process(p, nil)

	if action != engine.ActionModified {
		t.Errorf("Expected action %v, got %v", engine.ActionModified, action)
	}

	expectedPayload := "PONG-FROM-JS"
	if string(p.Payload) != expectedPayload {
		t.Errorf("Expected payload %q, got %q", expectedPayload, string(p.Payload))
	}

	t.Logf("JS Interception verified! Modified: %s", string(p.Payload))
}
