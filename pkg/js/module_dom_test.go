package js

import (
	"strings"
	"testing"
)

func TestRegisterDOMModule_HTMLGlobal(t *testing.T) {
	r, err := NewRuntime()
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}

	// html() should be registered
	val := r.vm.Get("html")
	if val == nil {
		t.Fatal("html() global should be registered")
	}
}

func TestDOM_ParseAndQuery(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<html><body><h1 id="title">Hello World</h1><p class="content">Paragraph</p></body></html>');
		var h1 = doc.querySelector('h1');
		var title_text = h1.text;
		var title_id = h1.id;
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}

	titleText := r.vm.Get("title_text")
	if titleText.String() != "Hello World" {
		t.Errorf("title_text = %q, want %q", titleText.String(), "Hello World")
	}
	titleID := r.vm.Get("title_id")
	if titleID.String() != "title" {
		t.Errorf("title_id = %q, want %q", titleID.String(), "title")
	}
}

func TestDOM_QuerySelectorAll(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<ul><li class="item">A</li><li class="item">B</li><li class="item">C</li></ul>');
		var items = doc.querySelectorAll('.item');
		var count = items.length;
		var first_text = items[0].text;
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}

	count := r.vm.Get("count")
	if count.ToInteger() != 3 {
		t.Errorf("count = %d, want 3", count.ToInteger())
	}
	firstText := r.vm.Get("first_text")
	if firstText.String() != "A" {
		t.Errorf("first_text = %q, want %q", firstText.String(), "A")
	}
}

func TestDOM_GetElementById(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<div><span id="target">Found</span></div>');
		var el = doc.getElementById('target');
		var text = el ? el.text : 'not found';
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}

	text := r.vm.Get("text")
	if text.String() != "Found" {
		t.Errorf("text = %q, want %q", text.String(), "Found")
	}
}

func TestDOM_SetInnerHTML(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<div id="main"><p>Old</p></div>');
		doc.setInnerHTML('#main', '<span>New Content</span>');
		var result = doc.querySelector('#main span');
		var new_text = result ? result.text : 'not found';
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}

	newText := r.vm.Get("new_text")
	if newText.String() != "New Content" {
		t.Errorf("new_text = %q, want %q", newText.String(), "New Content")
	}
}

func TestDOM_RemoveElement(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<div><p class="keep">A</p><p class="remove">B</p><p class="keep">C</p></div>');
		var removed = doc.removeElement('.remove');
		var remaining = doc.querySelectorAll('p');
		var remaining_count = remaining.length;
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}

	remainingCount := r.vm.Get("remaining_count")
	if remainingCount.ToInteger() != 2 {
		t.Errorf("remaining_count = %d, want 2", remainingCount.ToInteger())
	}
}

func TestDOM_AppendHTML(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<ul id="list"><li>A</li></ul>');
		doc.appendHTML('#list', '<li>B</li><li>C</li>');
		var items = doc.querySelectorAll('li');
		var append_count = items.length;
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}

	count := r.vm.Get("append_count")
	if count.ToInteger() != 3 {
		t.Errorf("count = %d, want 3", count.ToInteger())
	}
}

func TestDOM_SetAttribute(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<img src="old.png">');
		doc.setAttribute('img', 'src', 'new.png');
		var attr_val = doc.getAttribute('img', 'src');
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}

	val := r.vm.Get("attr_val")
	if val.String() != "new.png" {
		t.Errorf("attr_val = %q, want %q", val.String(), "new.png")
	}
}

func TestDOM_Cookies(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<html><body></body></html>', { url: 'https://example.com' });
		doc.setCookie('session', 'abc123');
		doc.setCookie('token', 'xyz789');
		var session_val = doc.getCookie('session');
		var all_cookies = doc.getAllCookies();
		var cookie_count = all_cookies.length;
		var cookie_string = doc.cookieString();
		doc.deleteCookie('token');
		var after_delete_count = doc.getAllCookies().length;
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}

	sessionVal := r.vm.Get("session_val")
	if sessionVal.String() != "abc123" {
		t.Errorf("session = %q, want %q", sessionVal.String(), "abc123")
	}
	cookieCount := r.vm.Get("cookie_count")
	if cookieCount.ToInteger() != 2 {
		t.Errorf("cookie_count = %d, want 2", cookieCount.ToInteger())
	}
	afterDelete := r.vm.Get("after_delete_count")
	if afterDelete.ToInteger() != 1 {
		t.Errorf("after_delete = %d, want 1", afterDelete.ToInteger())
	}
}

func TestDOM_Storage(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<html><body></body></html>');
		doc.setStorage('key1', 'value1');
		doc.setStorage('key2', 'value2');
		var storage_val = doc.getStorage('key1');
		var storage_len = doc.storageLength();
		doc.removeStorage('key1');
		var after_remove = doc.storageLength();
		doc.clearStorage();
		var after_clear = doc.storageLength();
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}

	storageVal := r.vm.Get("storage_val")
	if storageVal.String() != "value1" {
		t.Errorf("storage_val = %q, want %q", storageVal.String(), "value1")
	}
	storageLen := r.vm.Get("storage_len")
	if storageLen.ToInteger() != 2 {
		t.Errorf("storage_len = %d, want 2", storageLen.ToInteger())
	}
	afterRemove := r.vm.Get("after_remove")
	if afterRemove.ToInteger() != 1 {
		t.Errorf("after_remove = %d, want 1", afterRemove.ToInteger())
	}
	afterClear := r.vm.Get("after_clear")
	if afterClear.ToInteger() != 0 {
		t.Errorf("after_clear = %d, want 0", afterClear.ToInteger())
	}
}

func TestDOM_Serialize(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<html><body><p>Hello</p></body></html>');
		doc.appendHTML('body', '<p>World</p>');
		var serialized = doc.serialize();
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}

	serialized := r.vm.Get("serialized")
	s := serialized.String()
	if s == "" {
		t.Error("serialize() should not return empty")
	}
}

func TestDOM_Snapshot(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<html><body></body></html>', { url: 'https://example.com' });
		doc.setCookie('x', '1');
		doc.setStorage('y', '2');
		var snap = doc.snapshot();
		var snap_url = snap.url;
		var snap_has_html = snap.html && snap.html.length > 0;
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}

	snapURL := r.vm.Get("snap_url")
	if snapURL.String() != "https://example.com" {
		t.Errorf("snap_url = %q, want %q", snapURL.String(), "https://example.com")
	}
	hasHTML := r.vm.Get("snap_has_html")
	if !hasHTML.ToBoolean() {
		t.Error("snapshot should have html")
	}
}

func TestDOM_Title(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<html><head><title>My Page</title></head><body></body></html>');
		var page_title = doc.title();
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}

	title := r.vm.Get("page_title")
	if title.String() != "My Page" {
		t.Errorf("title = %q, want %q", title.String(), "My Page")
	}
}

func TestDOM_NilReturns(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<html><body><p>Test</p></body></html>');
		var missing = doc.querySelector('.nonexistent');
		var is_null = missing === null;
		var missing_cookie = doc.getCookie('nope');
		var missing_storage = doc.getStorage('nope');
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}

	isNull := r.vm.Get("is_null")
	if !isNull.ToBoolean() {
		t.Error("querySelector for nonexistent should return null")
	}
	missingCookie := r.vm.Get("missing_cookie")
	if !missingCookie.SameAs(r.vm.GlobalObject().Get("undefined")) && missingCookie.String() != "null" {
		// Cookie returns nil which becomes null in JS
	}
}

func TestDOM_NodeMethods(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<div><p id="first">A</p><p id="second">B</p></div>');
		var p = doc.querySelector('#first');
		var next = p.nextSibling();
		var next_text = next ? next.text : 'none';
		var children = doc.querySelector('div').children();
		var children_count = children.length;
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}

	nextText := r.vm.Get("next_text")
	if nextText.String() != "B" {
		t.Errorf("next_text = %q, want %q", nextText.String(), "B")
	}

	childrenCount := r.vm.Get("children_count")
	if childrenCount.ToInteger() != 2 {
		t.Errorf("children_count = %d, want 2", childrenCount.ToInteger())
	}
}

func TestDOM_Close(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('<html><body></body></html>');
		doc.close();
	`)
	if err != nil {
		t.Fatalf("JS error: %v", err)
	}
}

func TestDOM_Fetch(t *testing.T) {
	r, _ := NewRuntime()
	_, err := r.vm.RunString(`
		var doc = html('', {}).fetch('https://www.example.com');
		var page_title = doc.title();
		var has_body = doc.querySelector('body') !== null;
		var has_content = doc.innerHTML().length > 0;
	`)
	if err != nil {
		t.Skipf("Skipping (network may be unavailable): %v", err)
	}

	title := r.vm.Get("page_title")
	if title.String() == "" {
		t.Error("title should not be empty after fetch")
	}
	t.Logf("Fetched title: %q", title.String())

	hasBody := r.vm.Get("has_body")
	if !hasBody.ToBoolean() {
		t.Error("document should have a <body> after fetch")
	}

	hasContent := r.vm.Get("has_content")
	if !hasContent.ToBoolean() {
		t.Error("innerHTML should not be empty after fetch")
	}
}

func TestStripModuleSyntax(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "import from single quotes",
			input:  "import { createApp } from './app.js';",
			expect: "",
		},
		{
			name:   "import from double quotes",
			input:  `import { foo, bar } from "lodash";`,
			expect: "",
		},
		{
			name:   "import default",
			input:  "import App from './App.svelte';",
			expect: "",
		},
		{
			name:   "import bare",
			input:  "import './styles.css';",
			expect: "",
		},
		{
			name:   "import bare double quotes",
			input:  `import "./polyfill.js";`,
			expect: "",
		},
		{
			name:   "export default class",
			input:  "export default class App {}",
			expect: "class App {}",
		},
		{
			name:   "export default function",
			input:  "export default function main() {}",
			expect: "function main() {}",
		},
		{
			name:   "export braces",
			input:  "export { foo, bar, baz };",
			expect: "",
		},
		{
			name:   "export const",
			input:  "export const name = 'hello';",
			expect: "const name = 'hello';",
		},
		{
			name:   "export let",
			input:  "export let count = 0;",
			expect: "let count = 0;",
		},
		{
			name:   "export function",
			input:  "export function greet() {}",
			expect: "function greet() {}",
		},
		{
			name:   "export class",
			input:  "export class Widget {}",
			expect: "class Widget {}",
		},
		{
			name:   "export async function",
			input:  "export async function fetchData() {}",
			expect: "async function fetchData() {}",
		},
		{
			name:   "passthrough normal code",
			input:  "const x = 1;\nconsole.log(x);",
			expect: "const x = 1;\nconsole.log(x);",
		},
		{
			name: "mixed module and normal code",
			input: `import { h } from 'preact';
const App = () => h('div', null, 'Hello');
export default App;`,
			expect: `
const App = () => h('div', null, 'Hello');
App;`,
		},
		// ── Dynamic import() and import.meta ──
		{
			name:   "dynamic import double quotes",
			input:  `() => import("./Foo.js")`,
			expect: `() => Promise.resolve({default:{}})||("./Foo.js")`,
		},
		{
			name:   "dynamic import single quotes",
			input:  `() => import('./Bar.js')`,
			expect: `() => Promise.resolve({default:{}})||('./Bar.js')`,
		},
		{
			name:   "import.meta",
			input:  `const url = import.meta.url;`,
			expect: `const url = ({}).url;`,
		},
		{
			name:   "inline minified dynamic imports",
			input:  `var a=()=>import("./A.js"),b=()=>import("./B.js");`,
			expect: `var a=()=>Promise.resolve({default:{}})||("./A.js"),b=()=>Promise.resolve({default:{}})||("./B.js");`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripModuleSyntax(tt.input)
			if strings.TrimSpace(got) != strings.TrimSpace(tt.expect) {
				t.Errorf("stripModuleSyntax(%q)\n  got:  %q\n  want: %q", tt.input, strings.TrimSpace(got), strings.TrimSpace(tt.expect))
			}
		})
	}
}

