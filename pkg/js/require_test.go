package js

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dop251/goja"
)

func TestNewRequireManager(t *testing.T) {
	vm := goja.New()
	rm := NewRequireManager(vm, "/tmp")
	if rm == nil {
		t.Fatal("NewRequireManager should not return nil")
	}
	if rm.baseDir != "/tmp" {
		t.Errorf("Expected baseDir '/tmp', got '%s'", rm.baseDir)
	}
	if rm.cache == nil {
		t.Error("cache should be initialized")
	}
}

func TestRequireManager_Require_FileNotFound(t *testing.T) {
	vm := goja.New()
	rm := NewRequireManager(vm, "/tmp/nonexistent")
	_, err := rm.Require("./nonexistent_module.js")
	if err == nil {
		t.Error("Require should fail for nonexistent file")
	}
}

func TestRequireManager_Require_ValidJS(t *testing.T) {
	// Create a temp JS file
	tmpDir := t.TempDir()
	modPath := filepath.Join(tmpDir, "test_module.js")
	err := os.WriteFile(modPath, []byte(`
		exports.hello = function() { return "world"; };
		exports.num = 42;
	`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	vm := goja.New()
	rm := NewRequireManager(vm, tmpDir)
	result, err := rm.Require("./test_module.js")
	if err != nil {
		t.Fatalf("Require failed: %v", err)
	}
	if result == nil || goja.IsUndefined(result) {
		t.Fatal("Result should not be undefined")
	}

	// Verify exports
	obj := result.ToObject(vm)
	numVal := obj.Get("num")
	if numVal.ToInteger() != 42 {
		t.Errorf("Expected num=42, got %v", numVal)
	}
}

func TestRequireManager_Require_CircularDeps(t *testing.T) {
	// Create two modules that require each other
	tmpDir := t.TempDir()

	err := os.WriteFile(filepath.Join(tmpDir, "a.js"), []byte(`
		var b = require("./b.js");
		exports.fromA = "hello from A";
		exports.bVal = b.fromB;
	`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(tmpDir, "b.js"), []byte(`
		var a = require("./a.js");
		exports.fromB = "hello from B";
	`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	vm := goja.New()
	rm := NewRequireManager(vm, tmpDir)

	// Should not hang or panic (circular deps are handled by pre-caching)
	result, err := rm.Require("./a.js")
	if err != nil {
		t.Fatalf("Circular require should not fail: %v", err)
	}
	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

func TestRequireManager_Require_Cache(t *testing.T) {
	tmpDir := t.TempDir()
	modPath := filepath.Join(tmpDir, "cached.js")
	err := os.WriteFile(modPath, []byte(`exports.count = 1;`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	vm := goja.New()
	rm := NewRequireManager(vm, tmpDir)

	// First call
	r1, err := rm.Require("./cached.js")
	if err != nil {
		t.Fatal(err)
	}

	// Second call should return cached version (same object)
	r2, err := rm.Require("./cached.js")
	if err != nil {
		t.Fatal(err)
	}

	if r1 != r2 {
		t.Error("Cached module should return same object reference")
	}
}

func TestRequireManager_Require_SyntaxError(t *testing.T) {
	tmpDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, "bad.js"), []byte(`
		this is not valid javascript!!!
	`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	vm := goja.New()
	rm := NewRequireManager(vm, tmpDir)
	_, err = rm.Require("./bad.js")
	if err == nil {
		t.Error("Require should fail for syntax error")
	}
}

func TestRequireManager_Require_SyntaxError_NotCached(t *testing.T) {
	tmpDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, "bad2.js"), []byte(`{{{{`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	vm := goja.New()
	rm := NewRequireManager(vm, tmpDir)
	rm.Require("./bad2.js") // ignore error

	// Should not be cached
	rm.mu.Lock()
	_, cached := rm.cache[filepath.Join(tmpDir, "bad2.js")]
	rm.mu.Unlock()

	// Check cache is empty for this path (it may have different abs path format)
	if cached {
		t.Error("Failed module should not remain in cache")
	}
}

func TestRequireManager_Require_AutoAddJSExtension(t *testing.T) {
	tmpDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, "mymod.js"), []byte(`exports.ok = true;`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	vm := goja.New()
	rm := NewRequireManager(vm, tmpDir)
	result, err := rm.Require("./mymod") // no .js extension
	if err != nil {
		t.Fatalf("Should auto-add .js extension: %v", err)
	}

	obj := result.ToObject(vm)
	if !obj.Get("ok").ToBoolean() {
		t.Error("Expected ok=true")
	}
}

func TestRequireManager_Require_ModuleExports_Reassign(t *testing.T) {
	tmpDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, "reassign.js"), []byte(`
		module.exports = { greeting: "hi" };
	`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	vm := goja.New()
	rm := NewRequireManager(vm, tmpDir)
	result, err := rm.Require("./reassign.js")
	if err != nil {
		t.Fatal(err)
	}

	obj := result.ToObject(vm)
	greeting := obj.Get("greeting")
	if greeting.String() != "hi" {
		t.Errorf("Expected 'hi', got '%s'", greeting.String())
	}
}

// --- Benchmarks ---

func BenchmarkRequire_Cached(b *testing.B) {
	tmpDir := b.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "bench.js"), []byte(`exports.x = 1;`), 0644)

	vm := goja.New()
	rm := NewRequireManager(vm, tmpDir)
	rm.Require("./bench.js") // prime cache

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rm.Require("./bench.js")
	}
}

func BenchmarkRequire_Uncached(b *testing.B) {
	tmpDir := b.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "bench2.js"), []byte(`exports.x = 1;`), 0644)

	vm := goja.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rm := NewRequireManager(vm, tmpDir)
		rm.Require("./bench2.js")
	}
}
