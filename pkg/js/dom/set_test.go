package dom

import (
	"testing"
	"github.com/dop251/goja"
)

func TestGojaSetSupport(t *testing.T) {
	vm := goja.New()

	// Test 1: typeof Set
	val, err := vm.RunString(`typeof Set`)
	if err != nil {
		t.Fatalf("typeof Set error: %v", err)
	}
	t.Logf("typeof Set = %v", val)

	// Test 2: Set operations
	val, err = vm.RunString(`var s = new Set(); s.add("hello"); s.has("hello")`)
	if err != nil {
		t.Logf("Set basic error: %v", err)
	} else {
		t.Logf("Set basic result: %v", val)
	}

	// Test 3: Set on object property
	val, err = vm.RunString(`var obj = {}; obj["__t"] = new Set(); obj["__t"].add("foo"); obj["__t"].has("foo")`)
	if err != nil {
		t.Logf("Set on obj error: %v", err)
	} else {
		t.Logf("Set on obj result: %v", val)
	}

	// Test 4: BrowserEnv document.documentElement
	doc, _ := ParseWithURL(`<html><body><div id="root"></div></body></html>`, "https://example.com")
	vm2 := goja.New()
	env := NewBrowserEnv(doc, vm2)
	env.InjectGlobals()

	val, err = env.VM.RunString(`typeof document.documentElement`)
	t.Logf("typeof document.documentElement = %v (err=%v)", val, err)

	val, err = env.VM.RunString(`document.documentElement === null ? 'null' : document.documentElement === undefined ? 'undefined' : 'object'`)
	t.Logf("document.documentElement is: %v (err=%v)", val, err)

	// Test 5: Set on WrapNode element
	val, err = env.VM.RunString(`
		var el = document.getElementById('root');
		el["__test__"] = new Set();
		el["__test__"].add("bar");
		el["__test__"].has("bar")
	`)
	t.Logf("Set on WrapNode: %v (err=%v)", val, err)
}
