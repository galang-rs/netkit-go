package js

import (
	"testing"

	"http-interperation/pkg/browser"

	"github.com/dop251/goja"
)

func TestFetch_FingerprintSnapshoot(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	vm := runtime.vm

	// Test case: 1. Fetch and snapshoot, 2. Reuse snapshoot
	script := `
	async function test() {
		const resp1 = await fetch("https://www.google.com");
		if (typeof resp1.fingerprint.snapshoot !== 'function') {
			throw new Error("resp1.fingerprint.snapshoot is not a function");
		}
		const fp = resp1.fingerprint.snapshoot();
		
		const resp2 = await fetch("https://www.google.com", { fingerprint: fp });
		return resp2.ok;
	}
	test();
	`

	val, err := vm.RunString(script)
	if err != nil {
		t.Fatalf("JS Execution failed: %v", err)
	}

	promise, ok := val.Export().(*goja.Promise)
	if !ok {
		t.Fatalf("Expected promise, got %T", val.Export())
	}

	// Wait for promise
	for promise.State() == goja.PromiseStatePending {
		// In a real test we might need a way to advance time if there were timers,
		// but here it's just a promise resolve from fetch.
		// Since fetch is synchronous in our bridge (it wait for Sandbox.Fetch),
		// the promise should be resolved immediately after RunString.
	}

	if promise.State() == goja.PromiseStateRejected {
		t.Fatalf("Promise rejected: %v", promise.Result().Export())
	}

	result := promise.Result().Export()
	if ok, _ := result.(bool); !ok {
		t.Errorf("Expected true, got %v", result)
	}
}

func TestFetch_FingerprintInjection(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	vm := runtime.vm

	// Create a profile manually
	profile, _ := browser.GenerateFromProfile("chrome")
	vm.Set("myProfile", profile)

	script := `
	async function test() {
		const resp = await fetch("https://www.google.com", { fingerprint: myProfile });
		return resp.ok;
	}
	test();
	`

	val, err := vm.RunString(script)
	if err != nil {
		t.Fatalf("JS Execution failed: %v", err)
	}

	promise := val.Export().(*goja.Promise)
	if promise.State() == goja.PromiseStateRejected {
		t.Fatalf("Promise rejected: %v", promise.Result().Export())
	}

	result := promise.Result().Export()
	if ok, _ := result.(bool); !ok {
		t.Errorf("Expected true, got %v", result)
	}
}
