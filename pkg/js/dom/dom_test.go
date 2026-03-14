package dom

import (
	"testing"
)

// ──────── Parser Tests ────────

func TestParse_BasicHTML(t *testing.T) {
	doc, err := Parse("<html><head><title>Test</title></head><body><h1>Hello</h1></body></html>")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if doc.Root == nil {
		t.Fatal("Root should not be nil")
	}
	if doc.Title() != "Test" {
		t.Errorf("Title = %q, want %q", doc.Title(), "Test")
	}
	body := doc.Body()
	if body == nil {
		t.Fatal("Body should not be nil")
	}
}

func TestParse_NestedElements(t *testing.T) {
	doc, err := Parse("<div><ul><li>A</li><li>B</li><li>C</li></ul></div>")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	items := doc.Root.GetElementsByTagName("li")
	if len(items) != 3 {
		t.Errorf("Expected 3 <li> elements, got %d", len(items))
	}
	if items[0].TextContent() != "A" {
		t.Errorf("First <li> text = %q, want %q", items[0].TextContent(), "A")
	}
}

func TestParse_SelfClosingTags(t *testing.T) {
	doc, err := Parse(`<div><img src="test.png"><br><input type="text"></div>`)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	imgs := doc.Root.GetElementsByTagName("img")
	if len(imgs) != 1 {
		t.Errorf("Expected 1 <img>, got %d", len(imgs))
	}
	if imgs[0].GetAttribute("src") != "test.png" {
		t.Errorf("img src = %q, want %q", imgs[0].GetAttribute("src"), "test.png")
	}
}

func TestParse_Attributes(t *testing.T) {
	doc, err := Parse(`<div id="main" class="container active" data-value="test"></div>`)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	div := doc.Root.GetElementsByTagName("div")
	if len(div) == 0 {
		t.Fatal("Expected <div>")
	}
	if div[0].ID() != "main" {
		t.Errorf("id = %q, want %q", div[0].ID(), "main")
	}
	if !div[0].HasClass("container") || !div[0].HasClass("active") {
		t.Error("Expected classes: container, active")
	}
	if div[0].GetAttribute("data-value") != "test" {
		t.Errorf("data-value = %q, want %q", div[0].GetAttribute("data-value"), "test")
	}
}

func TestParse_Comments(t *testing.T) {
	doc, err := Parse("<div><!-- comment --><p>Text</p></div>")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	divs := doc.Root.GetElementsByTagName("div")
	if len(divs) == 0 {
		t.Fatal("Expected <div>")
	}
	hasComment := false
	for _, c := range divs[0].Children {
		if c.Type == CommentNode {
			hasComment = true
			if c.Text != " comment " {
				t.Errorf("comment text = %q, want %q", c.Text, " comment ")
			}
		}
	}
	if !hasComment {
		t.Error("Expected a comment node")
	}
}

func TestParseFragment(t *testing.T) {
	nodes, err := ParseFragment("<li>A</li><li>B</li>")
	if err != nil {
		t.Fatalf("ParseFragment error: %v", err)
	}
	if len(nodes) != 2 {
		t.Errorf("Expected 2 nodes, got %d", len(nodes))
	}
	if nodes[0].TextContent() != "A" {
		t.Errorf("First node text = %q, want %q", nodes[0].TextContent(), "A")
	}
}

func TestParseWithURL(t *testing.T) {
	doc, err := ParseWithURL("<html><body>Hi</body></html>", "https://example.com")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if doc.URL != "https://example.com" {
		t.Errorf("URL = %q, want %q", doc.URL, "https://example.com")
	}
}

// ──────── Node Tests ────────

func TestNode_TextContent(t *testing.T) {
	doc, _ := Parse("<div>Hello <span>World</span></div>")
	divs := doc.Root.GetElementsByTagName("div")
	if len(divs) == 0 {
		t.Fatal("Expected <div>")
	}
	text := divs[0].TextContent()
	if text != "Hello World" {
		t.Errorf("TextContent = %q, want %q", text, "Hello World")
	}
}

func TestNode_AppendChild(t *testing.T) {
	parent := NewElement("div")
	child := NewElement("p")
	parent.AppendChild(child)

	if len(parent.Children) != 1 {
		t.Errorf("Expected 1 child, got %d", len(parent.Children))
	}
	if child.Parent != parent {
		t.Error("child.Parent should be parent")
	}
}

func TestNode_RemoveChild(t *testing.T) {
	parent := NewElement("div")
	child := NewElement("p")
	parent.AppendChild(child)
	parent.RemoveChild(child)

	if len(parent.Children) != 0 {
		t.Errorf("Expected 0 children, got %d", len(parent.Children))
	}
	if child.Parent != nil {
		t.Error("child.Parent should be nil")
	}
}

func TestNode_Remove(t *testing.T) {
	parent := NewElement("div")
	child := NewElement("p")
	parent.AppendChild(child)
	child.Remove()

	if len(parent.Children) != 0 {
		t.Error("Expected child to be removed from parent")
	}
}

func TestNode_InsertBefore(t *testing.T) {
	parent := NewElement("ul")
	li1 := NewElement("li")
	li3 := NewElement("li")
	parent.AppendChild(li1)
	parent.AppendChild(li3)

	li2 := NewElement("li")
	parent.InsertBefore(li2, li3)

	if len(parent.Children) != 3 {
		t.Errorf("Expected 3 children, got %d", len(parent.Children))
	}
	if parent.Children[1] != li2 {
		t.Error("li2 should be at index 1")
	}
}

func TestNode_ReplaceChild(t *testing.T) {
	parent := NewElement("div")
	old := NewElement("p")
	parent.AppendChild(old)

	newNode := NewElement("span")
	parent.ReplaceChild(newNode, old)

	if len(parent.Children) != 1 {
		t.Errorf("Expected 1 child, got %d", len(parent.Children))
	}
	if parent.Children[0].Tag != "span" {
		t.Error("Expected <span>")
	}
}

func TestNode_Clone(t *testing.T) {
	el := NewElement("div")
	el.SetAttribute("id", "test")
	child := NewElement("p")
	el.AppendChild(child)

	shallow := el.Clone(false)
	if shallow.ID() != "test" {
		t.Error("Clone should preserve attributes")
	}
	if len(shallow.Children) != 0 {
		t.Error("Shallow clone should have no children")
	}

	deep := el.Clone(true)
	if len(deep.Children) != 1 {
		t.Error("Deep clone should have 1 child")
	}
	if deep.Children[0] == child {
		t.Error("Deep clone children should be different objects")
	}
}

func TestNode_SetAttribute(t *testing.T) {
	el := NewElement("div")
	el.SetAttribute("id", "test")
	el.SetAttribute("class", "a b c")

	if el.ID() != "test" {
		t.Errorf("ID = %q, want %q", el.ID(), "test")
	}
	if !el.HasClass("b") {
		t.Error("Expected class 'b'")
	}
}

func TestNode_Siblings(t *testing.T) {
	parent := NewElement("div")
	a := NewElement("p")
	b := NewElement("span")
	c := NewElement("em")
	parent.AppendChild(a)
	parent.AppendChild(b)
	parent.AppendChild(c)

	if b.PreviousElementSibling() != a {
		t.Error("b.PreviousElementSibling should be a")
	}
	if b.NextElementSibling() != c {
		t.Error("b.NextElementSibling should be c")
	}
	if a.PreviousElementSibling() != nil {
		t.Error("a.PreviousElementSibling should be nil")
	}
	if c.NextElementSibling() != nil {
		t.Error("c.NextElementSibling should be nil")
	}
}

func TestNode_GetElementByID(t *testing.T) {
	doc, _ := Parse(`<div><p id="target">Found</p><span id="other">Not this</span></div>`)
	node := doc.GetElementByID("target")
	if node == nil {
		t.Fatal("Expected to find #target")
	}
	if node.TextContent() != "Found" {
		t.Errorf("TextContent = %q, want %q", node.TextContent(), "Found")
	}
}

func TestNode_GetElementsByTagName(t *testing.T) {
	doc, _ := Parse("<div><p>A</p><p>B</p><span>C</span></div>")
	ps := doc.Root.GetElementsByTagName("p")
	if len(ps) != 2 {
		t.Errorf("Expected 2 <p>, got %d", len(ps))
	}
}

func TestNode_GetElementsByClassName(t *testing.T) {
	doc, _ := Parse(`<div><p class="a">1</p><p class="a b">2</p><p class="b">3</p></div>`)
	nodes := doc.Root.GetElementsByClassName("a")
	if len(nodes) != 2 {
		t.Errorf("Expected 2 elements with class 'a', got %d", len(nodes))
	}
}

// ──────── Document Tests ────────

func TestDocument_Body(t *testing.T) {
	doc, _ := Parse("<html><body><p>Test</p></body></html>")
	body := doc.Body()
	if body == nil {
		t.Fatal("Body should not be nil")
	}
	if body.Tag != "body" {
		t.Errorf("Body tag = %q, want %q", body.Tag, "body")
	}
}

func TestDocument_Head(t *testing.T) {
	doc, _ := Parse("<html><head><title>T</title></head><body></body></html>")
	head := doc.Head()
	if head == nil {
		t.Fatal("Head should not be nil")
	}
}

func TestDocument_Title(t *testing.T) {
	doc, _ := Parse("<html><head><title>My Page</title></head><body></body></html>")
	if doc.Title() != "My Page" {
		t.Errorf("Title = %q, want %q", doc.Title(), "My Page")
	}
}
