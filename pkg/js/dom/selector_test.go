package dom

import (
	"testing"
)

func TestSelector_Tag(t *testing.T) {
	doc, _ := Parse("<div><p>A</p><span>B</span><p>C</p></div>")
	nodes := doc.QuerySelectorAll("p")
	if len(nodes) != 2 {
		t.Errorf("Expected 2 <p> elements, got %d", len(nodes))
	}
}

func TestSelector_ID(t *testing.T) {
	doc, _ := Parse(`<div><p id="main">Hello</p><p id="other">World</p></div>`)
	node := doc.QuerySelector("#main")
	if node == nil {
		t.Fatal("Expected to find #main")
	}
	if node.TextContent() != "Hello" {
		t.Errorf("TextContent = %q, want %q", node.TextContent(), "Hello")
	}
}

func TestSelector_Class(t *testing.T) {
	doc, _ := Parse(`<div><p class="item">A</p><p class="item active">B</p><p>C</p></div>`)
	nodes := doc.QuerySelectorAll(".item")
	if len(nodes) != 2 {
		t.Errorf("Expected 2 .item elements, got %d", len(nodes))
	}
}

func TestSelector_MultiClass(t *testing.T) {
	doc, _ := Parse(`<div><p class="a b">1</p><p class="a">2</p><p class="b">3</p></div>`)
	nodes := doc.QuerySelectorAll(".a.b")
	if len(nodes) != 1 {
		t.Errorf("Expected 1 .a.b element, got %d", len(nodes))
	}
}

func TestSelector_Attribute_Presence(t *testing.T) {
	doc, _ := Parse(`<div><input type="text"><input><select></select></div>`)
	nodes := doc.QuerySelectorAll("[type]")
	if len(nodes) != 1 {
		t.Errorf("Expected 1 [type] element, got %d", len(nodes))
	}
}

func TestSelector_Attribute_Exact(t *testing.T) {
	doc, _ := Parse(`<div><input type="text"><input type="email"></div>`)
	nodes := doc.QuerySelectorAll(`[type="text"]`)
	if len(nodes) != 1 {
		t.Errorf("Expected 1 [type='text'], got %d", len(nodes))
	}
}

func TestSelector_Attribute_Contains(t *testing.T) {
	doc, _ := Parse(`<div><a href="https://example.com">1</a><a href="https://other.com">2</a></div>`)
	nodes := doc.QuerySelectorAll(`[href*="example"]`)
	if len(nodes) != 1 {
		t.Errorf("Expected 1 [href*='example'], got %d", len(nodes))
	}
}

func TestSelector_Attribute_StartsWith(t *testing.T) {
	doc, _ := Parse(`<div><a href="https://a.com">1</a><a href="http://b.com">2</a></div>`)
	nodes := doc.QuerySelectorAll(`[href^="https"]`)
	if len(nodes) != 1 {
		t.Errorf("Expected 1 [href^='https'], got %d", len(nodes))
	}
}

func TestSelector_Attribute_EndsWith(t *testing.T) {
	doc, _ := Parse(`<div><img src="a.png"><img src="b.jpg"></div>`)
	nodes := doc.QuerySelectorAll(`[src$=".png"]`)
	if len(nodes) != 1 {
		t.Errorf("Expected 1 [src$='.png'], got %d", len(nodes))
	}
}

func TestSelector_Descendant(t *testing.T) {
	doc, _ := Parse("<div><ul><li>A</li><li>B</li></ul></div>")
	nodes := doc.QuerySelectorAll("div li")
	if len(nodes) != 2 {
		t.Errorf("Expected 2 'div li' matches, got %d", len(nodes))
	}
}

func TestSelector_Child(t *testing.T) {
	doc, _ := Parse("<div><p>Direct</p><span><p>Nested</p></span></div>")
	nodes := doc.QuerySelectorAll("div > p")
	if len(nodes) != 1 {
		t.Errorf("Expected 1 'div > p', got %d", len(nodes))
	}
	if nodes[0].TextContent() != "Direct" {
		t.Errorf("Expected 'Direct', got %q", nodes[0].TextContent())
	}
}

func TestSelector_Adjacent(t *testing.T) {
	doc, _ := Parse("<div><h1>Title</h1><p>First</p><p>Second</p></div>")
	nodes := doc.QuerySelectorAll("h1 + p")
	if len(nodes) != 1 {
		t.Errorf("Expected 1 'h1 + p', got %d", len(nodes))
	}
	if nodes[0].TextContent() != "First" {
		t.Errorf("Expected 'First', got %q", nodes[0].TextContent())
	}
}

func TestSelector_GeneralSibling(t *testing.T) {
	doc, _ := Parse("<div><h1>Title</h1><p>A</p><p>B</p></div>")
	nodes := doc.QuerySelectorAll("h1 ~ p")
	if len(nodes) != 2 {
		t.Errorf("Expected 2 'h1 ~ p', got %d", len(nodes))
	}
}

func TestSelector_Universal(t *testing.T) {
	doc, _ := Parse("<div><p>A</p><span>B</span></div>")
	nodes := doc.QuerySelectorAll("div > *")
	if len(nodes) != 2 {
		t.Errorf("Expected 2 'div > *', got %d", len(nodes))
	}
}

func TestSelector_Comma(t *testing.T) {
	doc, _ := Parse("<div><h1>A</h1><h2>B</h2><p>C</p></div>")
	nodes := doc.QuerySelectorAll("h1, h2")
	if len(nodes) != 2 {
		t.Errorf("Expected 2 'h1, h2', got %d", len(nodes))
	}
}

func TestSelector_Compound(t *testing.T) {
	doc, _ := Parse(`<div><p class="x" id="target">Match</p><p class="x">NoMatch</p></div>`)
	node := doc.QuerySelector("p.x#target")
	if node == nil {
		t.Fatal("Expected to find p.x#target")
	}
	if node.TextContent() != "Match" {
		t.Errorf("TextContent = %q, want %q", node.TextContent(), "Match")
	}
}

func TestSelector_PseudoFirstChild(t *testing.T) {
	doc, _ := Parse("<ul><li>A</li><li>B</li><li>C</li></ul>")
	node := doc.QuerySelector("li:first-child")
	if node == nil {
		t.Fatal("Expected to find li:first-child")
	}
	if node.TextContent() != "A" {
		t.Errorf("TextContent = %q, want %q", node.TextContent(), "A")
	}
}

func TestSelector_PseudoLastChild(t *testing.T) {
	doc, _ := Parse("<ul><li>A</li><li>B</li><li>C</li></ul>")
	node := doc.QuerySelector("li:last-child")
	if node == nil {
		t.Fatal("Expected to find li:last-child")
	}
	if node.TextContent() != "C" {
		t.Errorf("TextContent = %q, want %q", node.TextContent(), "C")
	}
}

func TestSelector_PseudoNthChild(t *testing.T) {
	doc, _ := Parse("<ul><li>A</li><li>B</li><li>C</li><li>D</li></ul>")

	// Even
	nodes := doc.QuerySelectorAll("li:nth-child(even)")
	if len(nodes) != 2 {
		t.Errorf("Expected 2 even children, got %d", len(nodes))
	}

	// Odd
	nodes = doc.QuerySelectorAll("li:nth-child(odd)")
	if len(nodes) != 2 {
		t.Errorf("Expected 2 odd children, got %d", len(nodes))
	}

	// Specific index
	node := doc.QuerySelector("li:nth-child(2)")
	if node == nil {
		t.Fatal("Expected li:nth-child(2)")
	}
	if node.TextContent() != "B" {
		t.Errorf("TextContent = %q, want %q", node.TextContent(), "B")
	}

	// 2n+1 (odd)
	nodes = doc.QuerySelectorAll("li:nth-child(2n+1)")
	if len(nodes) != 2 {
		t.Errorf("Expected 2 for 2n+1, got %d", len(nodes))
	}
}

func TestSelector_PseudoNot(t *testing.T) {
	doc, _ := Parse(`<div><p class="keep">A</p><p class="remove">B</p><p class="keep">C</p></div>`)
	nodes := doc.QuerySelectorAll("p:not(.remove)")
	if len(nodes) != 2 {
		t.Errorf("Expected 2 p:not(.remove), got %d", len(nodes))
	}
}

func TestSelector_PseudoEmpty(t *testing.T) {
	doc, _ := Parse("<div><p></p><p>Non-empty</p></div>")
	nodes := doc.QuerySelectorAll("p:empty")
	if len(nodes) != 1 {
		t.Errorf("Expected 1 empty <p>, got %d", len(nodes))
	}
}

func TestSelector_PseudoContains(t *testing.T) {
	doc, _ := Parse(`<div><p>Hello World</p><p>Goodbye</p></div>`)
	nodes := doc.QuerySelectorAll(`:contains("Hello")`)
	if len(nodes) == 0 {
		t.Error("Expected at least 1 match for :contains('Hello')")
	}
}

func TestSelector_Invalid(t *testing.T) {
	_, err := ParseSelector("")
	if err == nil {
		t.Error("Expected error for empty selector")
	}
}

// ──────── Serialize Tests ────────

func TestSerialize_RoundTrip(t *testing.T) {
	input := "<html><head><title>Test</title></head><body><p>Hello</p></body></html>"
	doc, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	output := Serialize(doc)
	if output == "" {
		t.Error("Serialize should not return empty string")
	}
	// Re-parse and check
	doc2, err := Parse(output)
	if err != nil {
		t.Fatalf("Re-parse error: %v", err)
	}
	if doc2.Title() != "Test" {
		t.Errorf("Title after round-trip = %q, want %q", doc2.Title(), "Test")
	}
}

func TestSerialize_VoidElements(t *testing.T) {
	doc, _ := Parse(`<div><br><img src="test.png"><input type="text"></div>`)
	output := Serialize(doc)
	// Void elements should NOT have closing tags
	if contains(output, "</br>") || contains(output, "</img>") || contains(output, "</input>") {
		t.Error("Void elements should not have closing tags")
	}
}

func TestSerializeNode(t *testing.T) {
	el := NewElement("p")
	el.SetAttribute("class", "highlight")
	el.AppendChild(NewTextNode("Hello"))
	output := SerializeNode(el)
	expected := `<p class="highlight">Hello</p>`
	if output != expected {
		t.Errorf("SerializeNode = %q, want %q", output, expected)
	}
}

func TestSerializeChildren(t *testing.T) {
	parent := NewElement("div")
	parent.AppendChild(NewElement("p"))
	parent.AppendChild(NewElement("span"))
	output := SerializeChildren(parent)
	expected := "<p></p><span></span>"
	if output != expected {
		t.Errorf("SerializeChildren = %q, want %q", output, expected)
	}
}

// ──────── Cookie Tests ────────

func TestCookieJar_SetGet(t *testing.T) {
	jar := NewCookieJar()
	jar.Set("session", "abc123", nil)

	val := jar.Get("session")
	if val != "abc123" {
		t.Errorf("Get = %q, want %q", val, "abc123")
	}
}

func TestCookieJar_Delete(t *testing.T) {
	jar := NewCookieJar()
	jar.Set("session", "abc123", nil)
	jar.Delete("session")

	val := jar.Get("session")
	if val != "" {
		t.Errorf("After delete, Get = %q, want empty", val)
	}
}

func TestCookieJar_String(t *testing.T) {
	jar := NewCookieJar()
	jar.Set("a", "1", nil)
	jar.Set("b", "2", nil)

	s := jar.String()
	if s != "a=1; b=2" {
		t.Errorf("String = %q, want %q", s, "a=1; b=2")
	}
}

func TestCookieJar_SetFromHeader(t *testing.T) {
	jar := NewCookieJar()
	jar.SetFromHeader("session=xyz; Path=/; Secure; HttpOnly")

	val := jar.Get("session")
	if val != "xyz" {
		t.Errorf("Get = %q, want %q", val, "xyz")
	}
	cookies := jar.GetAll()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}
	if !cookies[0].Secure {
		t.Error("Expected Secure flag")
	}
	if !cookies[0].HTTPOnly {
		t.Error("Expected HttpOnly flag")
	}
}

func TestCookieJar_ForURL(t *testing.T) {
	jar := NewCookieJar()
	jar.Set("a", "1", map[string]interface{}{"domain": "example.com"})
	jar.Set("b", "2", map[string]interface{}{"domain": "other.com"})

	cookies := jar.ForURL("https://example.com/path")
	if len(cookies) != 1 {
		t.Errorf("Expected 1 cookie for example.com, got %d", len(cookies))
	}
}

func TestCookieJar_Clear(t *testing.T) {
	jar := NewCookieJar()
	jar.Set("a", "1", nil)
	jar.Set("b", "2", nil)
	jar.Clear()
	if len(jar.GetAll()) != 0 {
		t.Error("Expected empty jar after clear")
	}
}

// ──────── Storage Tests ────────

func TestStorage_SetGetItem(t *testing.T) {
	s := NewStorage()
	s.SetItem("key", "value")

	val, ok := s.GetItem("key")
	if !ok || val != "value" {
		t.Errorf("GetItem = (%q, %v), want (%q, true)", val, ok, "value")
	}
}

func TestStorage_RemoveItem(t *testing.T) {
	s := NewStorage()
	s.SetItem("key", "value")
	s.RemoveItem("key")

	_, ok := s.GetItem("key")
	if ok {
		t.Error("Expected key to be removed")
	}
}

func TestStorage_Clear(t *testing.T) {
	s := NewStorage()
	s.SetItem("a", "1")
	s.SetItem("b", "2")
	s.Clear()

	if s.Length() != 0 {
		t.Errorf("Length = %d, want 0", s.Length())
	}
}

func TestStorage_Length(t *testing.T) {
	s := NewStorage()
	s.SetItem("a", "1")
	s.SetItem("b", "2")
	s.SetItem("c", "3")

	if s.Length() != 3 {
		t.Errorf("Length = %d, want 3", s.Length())
	}
}

func TestStorage_Key(t *testing.T) {
	s := NewStorage()
	s.SetItem("first", "1")
	s.SetItem("second", "2")

	if s.Key(0) != "first" {
		t.Errorf("Key(0) = %q, want %q", s.Key(0), "first")
	}
	if s.Key(1) != "second" {
		t.Errorf("Key(1) = %q, want %q", s.Key(1), "second")
	}
}

func TestStorage_Snapshot(t *testing.T) {
	s := NewStorage()
	s.SetItem("a", "1")
	s.SetItem("b", "2")
	snap := s.Snapshot()

	if len(snap) != 2 || snap["a"] != "1" || snap["b"] != "2" {
		t.Error("Snapshot mismatch")
	}
}

// ──────── Helper ────────

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
