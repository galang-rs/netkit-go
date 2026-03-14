package dom

import (
	"image/color"
	"os"
	"path/filepath"
	"testing"
)

// ──────── CSS Tests ────────

func TestParseColor_Hex(t *testing.T) {
	tests := []struct {
		input string
		want  color.RGBA
	}{
		{"#ff0000", color.RGBA{255, 0, 0, 255}},
		{"#00ff00", color.RGBA{0, 255, 0, 255}},
		{"#0000ff", color.RGBA{0, 0, 255, 255}},
		{"#fff", color.RGBA{255, 255, 255, 255}},
		{"#000", color.RGBA{0, 0, 0, 255}},
		{"#1a1a2e", color.RGBA{26, 26, 46, 255}},
	}
	for _, tt := range tests {
		c, ok := parseColor(tt.input)
		if !ok {
			t.Errorf("parseColor(%q) failed", tt.input)
			continue
		}
		if c != tt.want {
			t.Errorf("parseColor(%q) = %v, want %v", tt.input, c, tt.want)
		}
	}
}

func TestParseColor_Named(t *testing.T) {
	c, ok := parseColor("red")
	if !ok || c != (color.RGBA{255, 0, 0, 255}) {
		t.Errorf("parseColor('red') = %v, %v", c, ok)
	}
	c, ok = parseColor("cornflowerblue")
	if !ok || c != (color.RGBA{100, 149, 237, 255}) {
		t.Errorf("parseColor('cornflowerblue') = %v, %v", c, ok)
	}
}

func TestParseColor_RGB(t *testing.T) {
	c, ok := parseColor("rgb(255, 128, 0)")
	if !ok {
		t.Fatal("Expected rgb() to parse")
	}
	if c.R != 255 || c.G != 128 || c.B != 0 || c.A != 255 {
		t.Errorf("rgb(255,128,0) = %v", c)
	}
}

func TestParseColor_RGBA(t *testing.T) {
	c, ok := parseColor("rgba(100, 200, 50, 0.5)")
	if !ok {
		t.Fatal("Expected rgba() to parse")
	}
	if c.R != 100 || c.G != 200 || c.B != 50 {
		t.Errorf("rgba r/g/b = %d,%d,%d", c.R, c.G, c.B)
	}
	if c.A < 125 || c.A > 130 { // 0.5 * 255 ≈ 127
		t.Errorf("rgba alpha = %d, want ~127", c.A)
	}
}

func TestParseCSS_Rules(t *testing.T) {
	css := `
		h1 { color: red; font-size: 32px; }
		.box { background-color: #1a1a2e; padding: 10px; }
		#main { border: 2px solid blue; }
	`
	sheet := ParseCSS(css)
	if len(sheet.Rules) != 3 {
		t.Errorf("Expected 3 rules, got %d", len(sheet.Rules))
	}
}

func TestParseCSS_Comments(t *testing.T) {
	css := `/* comment */ h1 { color: red; } /* another */`
	sheet := ParseCSS(css)
	if len(sheet.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(sheet.Rules))
	}
}

func TestResolveStyle(t *testing.T) {
	doc, _ := Parse(`<html><head><style>h1{color:red;font-size:24px}</style></head><body><h1>Test</h1></body></html>`)
	sheet := CollectStyles(doc)
	h1 := doc.QuerySelector("h1")
	if h1 == nil {
		t.Fatal("Expected <h1>")
	}
	style := ResolveStyle(h1, sheet)
	if style.Color != (color.RGBA{255, 0, 0, 255}) {
		t.Errorf("h1 color = %v, want red", style.Color)
	}
	if style.FontSize != 24 {
		t.Errorf("h1 font-size = %d, want 24", style.FontSize)
	}
}

func TestResolveStyle_InlineOverride(t *testing.T) {
	doc, _ := Parse(`<html><head><style>p{color:blue}</style></head><body><p style="color:green">Test</p></body></html>`)
	sheet := CollectStyles(doc)
	p := doc.QuerySelector("p")
	style := ResolveStyle(p, sheet)
	if style.Color != (color.RGBA{0, 128, 0, 255}) {
		t.Errorf("inline color = %v, want green", style.Color)
	}
}

func TestDefaultStyle_Display(t *testing.T) {
	tests := map[string]string{
		"div":    "block",
		"span":   "inline",
		"script": "none",
		"h1":     "block",
		"p":      "block",
	}
	for tag, want := range tests {
		s := DefaultStyle(tag)
		if s.Display != want {
			t.Errorf("DefaultStyle(%q).Display = %q, want %q", tag, s.Display, want)
		}
	}
}

func TestParsePx(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"16px", 16},
		{"32", 32},
		{"2em", 32},
		{"12pt", 15},
		{"auto", 0},
	}
	for _, tt := range tests {
		got := parsePx(tt.input, 0)
		if got != tt.want {
			t.Errorf("parsePx(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestParseBorderShorthand(t *testing.T) {
	style := DefaultStyle("div")
	parseBorderShorthand(style, "2px solid red")
	if style.BorderTop != 2 || style.BorderStyle != "solid" || style.BorderColor != (color.RGBA{255, 0, 0, 255}) {
		t.Errorf("border shorthand: top=%d style=%s color=%v", style.BorderTop, style.BorderStyle, style.BorderColor)
	}
}

// ──────── Layout Tests ────────

func TestLayout_BasicStructure(t *testing.T) {
	doc, _ := Parse("<html><body><h1>Title</h1><p>Paragraph</p></body></html>")
	result := Layout(doc, 800, 600)
	if result == nil {
		t.Fatal("Layout returned nil")
	}
	if result.ViewportWidth != 800 {
		t.Errorf("ViewportWidth = %d, want 800", result.ViewportWidth)
	}
	if result.ContentHeight <= 0 {
		t.Error("ContentHeight should be > 0")
	}
}

func TestLayout_ContentHeight(t *testing.T) {
	doc, _ := Parse("<html><body><h1>Big Title</h1><p>Line 1</p><p>Line 2</p><p>Line 3</p></body></html>")
	result := Layout(doc, 800, 600)
	if result.ContentHeight <= 0 {
		t.Error("ContentHeight should be > 0")
	}
}

func TestLayout_DisplayNone(t *testing.T) {
	doc, _ := Parse(`<html><head><style>.hidden{display:none}</style></head><body><p>Visible</p><p class="hidden">Hidden</p></body></html>`)
	result := Layout(doc, 800, 600)
	// The hidden element shouldn't contribute to layout
	boxCount := countBoxes(result.Root)
	if boxCount < 1 {
		t.Error("Expected at least 1 visible box")
	}
}

func countBoxes(box *LayoutBox) int {
	count := 1
	for _, child := range box.Children {
		count += countBoxes(child)
	}
	return count
}

// ──────── Render Tests ────────

func TestScreenshot_CreatesFile(t *testing.T) {
	doc, _ := Parse(`<html><head><style>body{background:#1a1a2e;color:white}h1{color:red;font-size:32px}.box{background:#16213e;padding:10px;margin:5px;border:2px solid #0f3460}</style></head><body><h1>Hello World</h1><div class="box">Content A</div><div class="box">Content B</div></body></html>`)

	tmpDir := filepath.Join(os.TempDir(), "dom_test_screenshots")
	doc.TempFiles = NewTempStore(tmpDir)
	defer doc.TempFiles.Cleanup()
	defer os.RemoveAll(tmpDir)

	path, err := Screenshot(doc, &RenderOptions{
		Width: 800, Height: 600,
	})
	if err != nil {
		t.Fatalf("Screenshot error: %v", err)
	}
	if path == "" {
		t.Fatal("Expected non-empty path")
	}
	// Check file exists
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Screenshot file not found: %v", err)
	}
	if info.Size() < 100 {
		t.Error("Screenshot file too small")
	}
}

func TestScreenshot_CustomPath(t *testing.T) {
	doc, _ := Parse("<html><body><h1>Test</h1></body></html>")
	tmpDir := filepath.Join(os.TempDir(), "dom_test_custom")
	defer os.RemoveAll(tmpDir)

	outPath := filepath.Join(tmpDir, "custom.png")
	path, err := Screenshot(doc, &RenderOptions{
		Width: 400, Height: 300, Path: outPath,
	})
	if err != nil {
		t.Fatalf("Screenshot error: %v", err)
	}
	if path != outPath {
		t.Errorf("Path = %q, want %q", path, outPath)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("Custom path file not found: %v", err)
	}
	os.Remove(outPath)
}

func TestScreenshot_FullPage(t *testing.T) {
	// Create a tall page
	html := "<html><body>"
	for i := 0; i < 50; i++ {
		html += "<p>Paragraph line content here</p>"
	}
	html += "</body></html>"
	doc, _ := Parse(html)

	tmpDir := filepath.Join(os.TempDir(), "dom_test_fullpage")
	doc.TempFiles = NewTempStore(tmpDir)
	defer doc.TempFiles.Cleanup()
	defer os.RemoveAll(tmpDir)

	path, err := Screenshot(doc, &RenderOptions{
		Width: 800, Height: 600, FullPage: true,
	})
	if err != nil {
		t.Fatalf("Screenshot error: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("File not found: %v", err)
	}
	if info.Size() < 100 {
		t.Error("Full page screenshot too small")
	}
}

func TestScreenshot_ScrollY(t *testing.T) {
	doc, _ := Parse("<html><body><h1>Top</h1><p>Bottom content here</p></body></html>")
	tmpDir := filepath.Join(os.TempDir(), "dom_test_scroll")
	doc.TempFiles = NewTempStore(tmpDir)
	defer doc.TempFiles.Cleanup()
	defer os.RemoveAll(tmpDir)

	_, err := Screenshot(doc, &RenderOptions{
		Width: 800, Height: 600, ScrollY: 100,
	})
	if err != nil {
		t.Fatalf("Screenshot with scrollY error: %v", err)
	}
}

// ──────── TempStore Tests ────────

func TestTempStore_AutoIncrement(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "dom_test_tempstore")
	defer os.RemoveAll(tmpDir)

	store := NewTempStore(tmpDir)
	p1 := store.NextPath("")
	p2 := store.NextPath("")
	p3 := store.NextPath("")

	if p1 != filepath.Join(tmpDir, "1.png") {
		t.Errorf("p1 = %q", p1)
	}
	if p2 != filepath.Join(tmpDir, "2.png") {
		t.Errorf("p2 = %q", p2)
	}
	if p3 != filepath.Join(tmpDir, "3.png") {
		t.Errorf("p3 = %q", p3)
	}
}

func TestTempStore_CustomPath(t *testing.T) {
	store := NewTempStore("")
	custom := filepath.Join(os.TempDir(), "custom_test.png")
	p := store.NextPath(custom)
	if p != custom {
		t.Errorf("custom path = %q, want %q", p, custom)
	}
}

func TestTempStore_Cleanup(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "dom_test_cleanup")
	defer os.RemoveAll(tmpDir)

	store := NewTempStore(tmpDir)
	// Create dummy files
	os.MkdirAll(tmpDir, 0755)
	f1 := filepath.Join(tmpDir, "test1.png")
	f2 := filepath.Join(tmpDir, "test2.png")
	os.WriteFile(f1, []byte("test"), 0644)
	os.WriteFile(f2, []byte("test"), 0644)
	store.Track(f1)
	store.Track(f2)

	if len(store.Files()) != 2 {
		t.Errorf("Expected 2 tracked files, got %d", len(store.Files()))
	}

	store.Cleanup()

	if _, err := os.Stat(f1); !os.IsNotExist(err) {
		t.Error("f1 should be deleted after cleanup")
	}
	if _, err := os.Stat(f2); !os.IsNotExist(err) {
		t.Error("f2 should be deleted after cleanup")
	}
}
