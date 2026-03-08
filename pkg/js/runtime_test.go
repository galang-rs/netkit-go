package js

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewRuntime(t *testing.T) {
	r, err := NewRuntime()
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	if r == nil {
		t.Fatal("Runtime should not be nil")
	}
	if r.vm == nil {
		t.Error("VM should be initialized")
	}
	if r.baseModules == nil {
		t.Error("baseModules should be initialized")
	}
}

func TestRuntime_LoadScript_FileNotFound(t *testing.T) {
	r, _ := NewRuntime()
	err := r.LoadScript("/tmp/nonexistent_script_xyz.js")
	if err == nil {
		t.Error("LoadScript should fail for nonexistent file")
	}
}

func TestRuntime_LoadScript_SyntaxError(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "bad.js")
	os.WriteFile(scriptPath, []byte(`{{{{ invalid JS`), 0644)

	r, _ := NewRuntime()
	err := r.LoadScript(scriptPath)
	if err == nil {
		t.Error("LoadScript should fail for syntax error")
	}
}

func TestRuntime_LoadScript_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "good.js")
	os.WriteFile(scriptPath, []byte(`
		var result = 1 + 2;
	`), 0644)

	r, _ := NewRuntime()
	err := r.LoadScript(scriptPath)
	if err != nil {
		t.Fatalf("LoadScript should succeed: %v", err)
	}
}

func TestRuntime_LoadScript_WithRequire(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "util.js"), []byte(`exports.add = function(a, b) { return a + b; };`), 0644)
	os.WriteFile(filepath.Join(tmpDir, "main.js"), []byte(`
		var util = require("./util.js");
		var sum = util.add(3, 4);
	`), 0644)

	r, _ := NewRuntime()
	err := r.LoadScript(filepath.Join(tmpDir, "main.js"))
	if err != nil {
		t.Fatalf("LoadScript with require should succeed: %v", err)
	}

	// Verify the sum was computed
	val := r.vm.Get("sum")
	if val.ToInteger() != 7 {
		t.Errorf("Expected sum=7, got %v", val)
	}
}

func TestRuntime_GlobalFunctions(t *testing.T) {
	r, _ := NewRuntime()

	// Test Reset callback
	var resetCalled bool
	r.OnReset = func() { resetCalled = true }

	resetFn := r.vm.Get("Reset")
	if resetFn == nil {
		t.Fatal("Reset should be registered")
	}

	r.vm.RunString("Reset()")
	if !resetCalled {
		t.Error("OnReset should have been called")
	}
}

func TestRuntime_DomainCallback(t *testing.T) {
	r, _ := NewRuntime()

	var domainVal string
	r.OnDomain = func(d string) { domainVal = d }

	r.vm.RunString(`Domain("example.com")`)
	if domainVal != "example.com" {
		t.Errorf("Expected 'example.com', got '%s'", domainVal)
	}
}

func TestRuntime_ConsoleRegistered(t *testing.T) {
	r, _ := NewRuntime()
	// console.log should not panic
	_, err := r.vm.RunString(`console.log("test")`)
	if err != nil {
		t.Errorf("console.log should work: %v", err)
	}
}

func TestRuntime_BaseModulesRegistered(t *testing.T) {
	r, _ := NewRuntime()
	// Check some key modules are registered
	modules := []string{"Net", "http", "DNS", "Crypto", "Traffic", "Metrics", "Sync", "Security", "MIME"}
	for _, mod := range modules {
		if r.baseModules[mod] == nil {
			t.Errorf("Base module '%s' should be registered", mod)
		}
	}
}

func TestRuntime_Mutex_Exists(t *testing.T) {
	r, _ := NewRuntime()
	// Mutex should be usable (not panic)
	r.mu.Lock()
	r.mu.Unlock()
}

// --- Benchmarks ---

func BenchmarkNewRuntime(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewRuntime()
	}
}

func BenchmarkLoadScript(b *testing.B) {
	tmpDir := b.TempDir()
	script := filepath.Join(tmpDir, "bench.js")
	os.WriteFile(script, []byte(`var x = 1 + 2;`), 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, _ := NewRuntime()
		r.LoadScript(script)
	}
}
