package dom

import (
	"image/color"
	"strconv"
	"strings"
)

// ──────────────────────────────────────────────
// CSS Style Types
// ──────────────────────────────────────────────

// ComputedStyle holds resolved CSS properties for a single element.
type ComputedStyle struct {
	// Colors
	Color           color.RGBA
	BackgroundColor color.RGBA
	BorderColor     color.RGBA

	// Box model (in px)
	PaddingTop    int
	PaddingRight  int
	PaddingBottom int
	PaddingLeft   int
	MarginTop     int
	MarginRight   int
	MarginBottom  int
	MarginLeft    int
	BorderTop     int
	BorderRight   int
	BorderBottom  int
	BorderLeft    int

	// Dimensions
	Width  int // 0 = auto
	Height int // 0 = auto

	// Typography
	FontSize       int // px
	FontWeight     int // 100-900
	LineHeight     int // px, 0 = auto
	TextAlign      string
	TextDecoration string

	// Display
	Display string // "block", "inline", "none", "inline-block"

	// Visual
	Opacity      float64
	BorderRadius int
	BorderStyle  string
}

// StyleRule represents a CSS rule: selector → properties.
type StyleRule struct {
	Selector   *SelectorGroup
	Properties map[string]string
}

// Stylesheet holds a collection of CSS rules.
type Stylesheet struct {
	Rules []StyleRule
}

// DefaultStyle returns the browser-default style for a given element.
func DefaultStyle(tag string) *ComputedStyle {
	s := &ComputedStyle{
		Color:           color.RGBA{0, 0, 0, 255},       // black text
		BackgroundColor: color.RGBA{0, 0, 0, 0},         // transparent bg
		BorderColor:     color.RGBA{0, 0, 0, 255},
		FontSize:        16,
		FontWeight:      400,
		Display:         "inline",
		Opacity:         1.0,
		TextAlign:       "left",
		BorderStyle:     "none",
	}
	switch tag {
	case "html", "body":
		s.Display = "block"
		s.BackgroundColor = color.RGBA{255, 255, 255, 255}
	case "div", "p", "h1", "h2", "h3", "h4", "h5", "h6",
		"ul", "ol", "li", "section", "article", "header",
		"footer", "main", "nav", "aside", "form", "fieldset",
		"table", "thead", "tbody", "tfoot", "tr",
		"blockquote", "pre", "figure", "figcaption",
		"details", "summary", "address", "hr":
		s.Display = "block"
	case "span", "a", "em", "strong", "b", "i", "u", "small",
		"code", "abbr", "cite", "sub", "sup", "label", "img":
		s.Display = "inline"
	case "br":
		s.Display = "block"
	case "script", "style", "link", "meta", "head", "title":
		s.Display = "none"
	}
	// Heading defaults
	switch tag {
	case "h1":
		s.FontSize = 32
		s.FontWeight = 700
		s.MarginTop = 21
		s.MarginBottom = 21
	case "h2":
		s.FontSize = 24
		s.FontWeight = 700
		s.MarginTop = 19
		s.MarginBottom = 19
	case "h3":
		s.FontSize = 18
		s.FontWeight = 700
		s.MarginTop = 18
		s.MarginBottom = 18
	case "h4":
		s.FontSize = 16
		s.FontWeight = 700
		s.MarginTop = 21
		s.MarginBottom = 21
	case "h5":
		s.FontSize = 13
		s.FontWeight = 700
		s.MarginTop = 22
		s.MarginBottom = 22
	case "h6":
		s.FontSize = 10
		s.FontWeight = 700
		s.MarginTop = 24
		s.MarginBottom = 24
	case "p":
		s.MarginTop = 16
		s.MarginBottom = 16
	case "ul", "ol":
		s.MarginTop = 16
		s.MarginBottom = 16
		s.PaddingLeft = 40
	case "li":
		s.Display = "list-item"
	case "hr":
		s.MarginTop = 8
		s.MarginBottom = 8
		s.BorderTop = 1
		s.BorderStyle = "solid"
		s.BorderColor = color.RGBA{128, 128, 128, 255}
	case "pre", "code":
		s.FontSize = 14
	case "blockquote":
		s.MarginTop = 16
		s.MarginBottom = 16
		s.MarginLeft = 40
		s.MarginRight = 40
	case "a":
		s.Color = color.RGBA{0, 0, 238, 255} // blue
		s.TextDecoration = "underline"
	case "strong", "b":
		s.FontWeight = 700
	case "em", "i":
		// italic not rendered yet but preserve for future
	}
	return s
}

// ──────────────────────────────────────────────
// CSS Parser
// ──────────────────────────────────────────────

// ParseCSS parses a CSS stylesheet string into a Stylesheet.
func ParseCSS(css string) *Stylesheet {
	sheet := &Stylesheet{}
	css = stripComments(css)
	rules := splitRules(css)
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		// Skip @rules for now
		if strings.HasPrefix(rule, "@") {
			continue
		}
		braceIdx := strings.Index(rule, "{")
		if braceIdx < 0 {
			continue
		}
		selectorStr := strings.TrimSpace(rule[:braceIdx])
		bodyStr := rule[braceIdx+1:]
		bodyStr = strings.TrimSuffix(strings.TrimSpace(bodyStr), "}")

		sel, err := ParseSelector(selectorStr)
		if err != nil {
			continue
		}
		props := parseDeclarations(bodyStr)
		if len(props) > 0 {
			sheet.Rules = append(sheet.Rules, StyleRule{
				Selector:   sel,
				Properties: props,
			})
		}
	}
	return sheet
}

// ParseInlineStyle parses a style="" attribute value.
func ParseInlineStyle(style string) map[string]string {
	return parseDeclarations(style)
}

func stripComments(css string) string {
	var sb strings.Builder
	i := 0
	for i < len(css) {
		if i+1 < len(css) && css[i] == '/' && css[i+1] == '*' {
			end := strings.Index(css[i+2:], "*/")
			if end >= 0 {
				i = i + 2 + end + 2
			} else {
				break
			}
		} else {
			sb.WriteByte(css[i])
			i++
		}
	}
	return sb.String()
}

func splitRules(css string) []string {
	var rules []string
	depth := 0
	start := 0
	for i := 0; i < len(css); i++ {
		switch css[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				rules = append(rules, css[start:i+1])
				start = i + 1
			}
		}
	}
	return rules
}

func parseDeclarations(body string) map[string]string {
	props := make(map[string]string)
	decls := strings.Split(body, ";")
	for _, decl := range decls {
		decl = strings.TrimSpace(decl)
		if decl == "" {
			continue
		}
		colonIdx := strings.Index(decl, ":")
		if colonIdx < 0 {
			continue
		}
		key := strings.TrimSpace(decl[:colonIdx])
		val := strings.TrimSpace(decl[colonIdx+1:])
		val = strings.TrimSuffix(val, "!important")
		val = strings.TrimSpace(val)
		props[strings.ToLower(key)] = val
	}
	return props
}

// ──────────────────────────────────────────────
// Style Resolution
// ──────────────────────────────────────────────

// CollectStyles parses all <style> elements in the document.
func CollectStyles(doc *Document) *Stylesheet {
	combined := &Stylesheet{}
	styles := doc.Root.GetElementsByTagName("style")
	for _, s := range styles {
		cssText := s.TextContent()
		sheet := ParseCSS(cssText)
		combined.Rules = append(combined.Rules, sheet.Rules...)
	}
	return combined
}

// ResolveStyle computes the final style for a node by applying:
// 1. Browser defaults, 2. Stylesheet rules, 3. Inline style attribute
func ResolveStyle(node *Node, sheet *Stylesheet) *ComputedStyle {
	style := DefaultStyle(node.Tag)

	// Apply stylesheet rules (later rules override earlier)
	for _, rule := range sheet.Rules {
		if rule.Selector.Match(node) {
			applyProperties(style, rule.Properties)
		}
	}

	// Apply inline style (highest priority)
	if inlineStr := node.GetAttribute("style"); inlineStr != "" {
		inlineProps := ParseInlineStyle(inlineStr)
		applyProperties(style, inlineProps)
	}

	return style
}

// applyProperties applies CSS property map onto a ComputedStyle.
func applyProperties(style *ComputedStyle, props map[string]string) {
	for key, val := range props {
		switch key {
		case "color":
			if c, ok := parseColor(val); ok {
				style.Color = c
			}
		case "background-color", "background":
			if c, ok := parseColor(val); ok {
				style.BackgroundColor = c
			}
		case "border-color":
			if c, ok := parseColor(val); ok {
				style.BorderColor = c
			}
		case "font-size":
			style.FontSize = parsePx(val, style.FontSize)
		case "font-weight":
			style.FontWeight = parseFontWeight(val)
		case "line-height":
			style.LineHeight = parsePx(val, 0)
		case "text-align":
			style.TextAlign = val
		case "text-decoration":
			style.TextDecoration = val
		case "display":
			style.Display = val
		case "width":
			style.Width = parsePx(val, 0)
		case "height":
			style.Height = parsePx(val, 0)
		case "opacity":
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				style.Opacity = f
			}
		case "border-radius":
			style.BorderRadius = parsePx(val, 0)
		case "border-style":
			style.BorderStyle = val
		case "border-width":
			px := parsePx(val, 0)
			style.BorderTop = px
			style.BorderRight = px
			style.BorderBottom = px
			style.BorderLeft = px
		case "border":
			parseBorderShorthand(style, val)

		// Padding shorthand + individual
		case "padding":
			parseBoxShorthand(val, &style.PaddingTop, &style.PaddingRight, &style.PaddingBottom, &style.PaddingLeft)
		case "padding-top":
			style.PaddingTop = parsePx(val, 0)
		case "padding-right":
			style.PaddingRight = parsePx(val, 0)
		case "padding-bottom":
			style.PaddingBottom = parsePx(val, 0)
		case "padding-left":
			style.PaddingLeft = parsePx(val, 0)

		// Margin shorthand + individual
		case "margin":
			parseBoxShorthand(val, &style.MarginTop, &style.MarginRight, &style.MarginBottom, &style.MarginLeft)
		case "margin-top":
			style.MarginTop = parsePx(val, 0)
		case "margin-right":
			style.MarginRight = parsePx(val, 0)
		case "margin-bottom":
			style.MarginBottom = parsePx(val, 0)
		case "margin-left":
			style.MarginLeft = parsePx(val, 0)
		}
	}
}

// ──────────────────────────────────────────────
// CSS Value Parsers
// ──────────────────────────────────────────────

// parsePx parses a CSS length value, returning pixels.
func parsePx(val string, fallback int) int {
	val = strings.TrimSpace(strings.ToLower(val))
	if val == "auto" || val == "" {
		return fallback
	}
	// Strip units
	for _, unit := range []string{"px", "pt", "em", "rem", "%"} {
		if strings.HasSuffix(val, unit) {
			numStr := strings.TrimSuffix(val, unit)
			if f, err := strconv.ParseFloat(numStr, 64); err == nil {
				switch unit {
				case "pt":
					return int(f * 1.333)
				case "em", "rem":
					return int(f * 16) // base 16px
				case "%":
					return fallback // percentage not supported in simple mode
				default:
					return int(f)
				}
			}
			return fallback
		}
	}
	// Plain number
	if f, err := strconv.ParseFloat(val, 64); err == nil {
		return int(f)
	}
	return fallback
}

func parseFontWeight(val string) int {
	val = strings.TrimSpace(strings.ToLower(val))
	switch val {
	case "normal":
		return 400
	case "bold":
		return 700
	case "lighter":
		return 300
	case "bolder":
		return 800
	}
	if w, err := strconv.Atoi(val); err == nil {
		return w
	}
	return 400
}

func parseBoxShorthand(val string, top, right, bottom, left *int) {
	parts := strings.Fields(val)
	switch len(parts) {
	case 1:
		v := parsePx(parts[0], 0)
		*top, *right, *bottom, *left = v, v, v, v
	case 2:
		tb := parsePx(parts[0], 0)
		lr := parsePx(parts[1], 0)
		*top, *bottom = tb, tb
		*right, *left = lr, lr
	case 3:
		*top = parsePx(parts[0], 0)
		*right = parsePx(parts[1], 0)
		*left = *right
		*bottom = parsePx(parts[2], 0)
	case 4:
		*top = parsePx(parts[0], 0)
		*right = parsePx(parts[1], 0)
		*bottom = parsePx(parts[2], 0)
		*left = parsePx(parts[3], 0)
	}
}

func parseBorderShorthand(style *ComputedStyle, val string) {
	parts := strings.Fields(val)
	for _, part := range parts {
		partLower := strings.ToLower(part)
		// Check if it's a border style
		switch partLower {
		case "solid", "dashed", "dotted", "double", "groove", "ridge", "inset", "outset", "none":
			style.BorderStyle = partLower
			continue
		}
		// Check if it's a color
		if c, ok := parseColor(part); ok {
			style.BorderColor = c
			continue
		}
		// Check if it's a width
		px := parsePx(part, -1)
		if px >= 0 {
			style.BorderTop = px
			style.BorderRight = px
			style.BorderBottom = px
			style.BorderLeft = px
		}
	}
}

// ──────────────────────────────────────────────
// Color Parser
// ──────────────────────────────────────────────

func parseColor(val string) (color.RGBA, bool) {
	val = strings.TrimSpace(strings.ToLower(val))
	if val == "" || val == "transparent" {
		return color.RGBA{0, 0, 0, 0}, val == "transparent"
	}

	// Named colors
	if c, ok := namedColors[val]; ok {
		return c, true
	}

	// #hex
	if strings.HasPrefix(val, "#") {
		return parseHex(val[1:])
	}

	// rgb() / rgba()
	if strings.HasPrefix(val, "rgb") {
		return parseRGB(val)
	}

	return color.RGBA{}, false
}

func parseHex(hex string) (color.RGBA, bool) {
	switch len(hex) {
	case 3: // #RGB → #RRGGBB
		r, _ := strconv.ParseUint(string(hex[0])+string(hex[0]), 16, 8)
		g, _ := strconv.ParseUint(string(hex[1])+string(hex[1]), 16, 8)
		b, _ := strconv.ParseUint(string(hex[2])+string(hex[2]), 16, 8)
		return color.RGBA{uint8(r), uint8(g), uint8(b), 255}, true
	case 4: // #RGBA
		r, _ := strconv.ParseUint(string(hex[0])+string(hex[0]), 16, 8)
		g, _ := strconv.ParseUint(string(hex[1])+string(hex[1]), 16, 8)
		b, _ := strconv.ParseUint(string(hex[2])+string(hex[2]), 16, 8)
		a, _ := strconv.ParseUint(string(hex[3])+string(hex[3]), 16, 8)
		return color.RGBA{uint8(r), uint8(g), uint8(b), uint8(a)}, true
	case 6: // #RRGGBB
		r, _ := strconv.ParseUint(hex[0:2], 16, 8)
		g, _ := strconv.ParseUint(hex[2:4], 16, 8)
		b, _ := strconv.ParseUint(hex[4:6], 16, 8)
		return color.RGBA{uint8(r), uint8(g), uint8(b), 255}, true
	case 8: // #RRGGBBAA
		r, _ := strconv.ParseUint(hex[0:2], 16, 8)
		g, _ := strconv.ParseUint(hex[2:4], 16, 8)
		b, _ := strconv.ParseUint(hex[4:6], 16, 8)
		a, _ := strconv.ParseUint(hex[6:8], 16, 8)
		return color.RGBA{uint8(r), uint8(g), uint8(b), uint8(a)}, true
	}
	return color.RGBA{}, false
}

func parseRGB(val string) (color.RGBA, bool) {
	// Extract content between parentheses
	start := strings.Index(val, "(")
	end := strings.LastIndex(val, ")")
	if start < 0 || end < 0 || end <= start {
		return color.RGBA{}, false
	}
	inner := val[start+1 : end]
	// Support both comma and space separator
	inner = strings.ReplaceAll(inner, "/", ",")
	parts := strings.Split(inner, ",")
	if len(parts) < 3 {
		parts = strings.Fields(inner)
	}
	if len(parts) < 3 {
		return color.RGBA{}, false
	}

	r := parseColorComponent(strings.TrimSpace(parts[0]))
	g := parseColorComponent(strings.TrimSpace(parts[1]))
	b := parseColorComponent(strings.TrimSpace(parts[2]))
	a := uint8(255)
	if len(parts) >= 4 {
		af, err := strconv.ParseFloat(strings.TrimSpace(parts[3]), 64)
		if err == nil {
			if af <= 1.0 {
				a = uint8(af * 255)
			} else {
				a = uint8(af)
			}
		}
	}
	return color.RGBA{r, g, b, a}, true
}

func parseColorComponent(s string) uint8 {
	if strings.HasSuffix(s, "%") {
		f, _ := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64)
		return uint8(f * 2.55)
	}
	v, _ := strconv.Atoi(s)
	if v > 255 {
		v = 255
	}
	if v < 0 {
		v = 0
	}
	return uint8(v)
}

// ──────────────────────────────────────────────
// Named CSS Colors (140 standard colors)
// ──────────────────────────────────────────────

var namedColors = map[string]color.RGBA{
	"aliceblue":            {240, 248, 255, 255},
	"antiquewhite":         {250, 235, 215, 255},
	"aqua":                 {0, 255, 255, 255},
	"aquamarine":           {127, 255, 212, 255},
	"azure":                {240, 255, 255, 255},
	"beige":                {245, 245, 220, 255},
	"bisque":               {255, 228, 196, 255},
	"black":                {0, 0, 0, 255},
	"blanchedalmond":       {255, 235, 205, 255},
	"blue":                 {0, 0, 255, 255},
	"blueviolet":           {138, 43, 226, 255},
	"brown":                {165, 42, 42, 255},
	"burlywood":            {222, 184, 135, 255},
	"cadetblue":            {95, 158, 160, 255},
	"chartreuse":           {127, 255, 0, 255},
	"chocolate":            {210, 105, 30, 255},
	"coral":                {255, 127, 80, 255},
	"cornflowerblue":       {100, 149, 237, 255},
	"cornsilk":             {255, 248, 220, 255},
	"crimson":              {220, 20, 60, 255},
	"cyan":                 {0, 255, 255, 255},
	"darkblue":             {0, 0, 139, 255},
	"darkcyan":             {0, 139, 139, 255},
	"darkgoldenrod":        {184, 134, 11, 255},
	"darkgray":             {169, 169, 169, 255},
	"darkgreen":            {0, 100, 0, 255},
	"darkgrey":             {169, 169, 169, 255},
	"darkkhaki":            {189, 183, 107, 255},
	"darkmagenta":          {139, 0, 139, 255},
	"darkolivegreen":       {85, 107, 47, 255},
	"darkorange":           {255, 140, 0, 255},
	"darkorchid":           {153, 50, 204, 255},
	"darkred":              {139, 0, 0, 255},
	"darksalmon":           {233, 150, 122, 255},
	"darkseagreen":         {143, 188, 143, 255},
	"darkslateblue":        {72, 61, 139, 255},
	"darkslategray":        {47, 79, 79, 255},
	"darkslategrey":        {47, 79, 79, 255},
	"darkturquoise":        {0, 206, 209, 255},
	"darkviolet":           {148, 0, 211, 255},
	"deeppink":             {255, 20, 147, 255},
	"deepskyblue":          {0, 191, 255, 255},
	"dimgray":              {105, 105, 105, 255},
	"dimgrey":              {105, 105, 105, 255},
	"dodgerblue":           {30, 144, 255, 255},
	"firebrick":            {178, 34, 34, 255},
	"floralwhite":          {255, 250, 240, 255},
	"forestgreen":          {34, 139, 34, 255},
	"fuchsia":              {255, 0, 255, 255},
	"gainsboro":            {220, 220, 220, 255},
	"ghostwhite":           {248, 248, 255, 255},
	"gold":                 {255, 215, 0, 255},
	"goldenrod":            {218, 165, 32, 255},
	"gray":                 {128, 128, 128, 255},
	"green":                {0, 128, 0, 255},
	"greenyellow":          {173, 255, 47, 255},
	"grey":                 {128, 128, 128, 255},
	"honeydew":             {240, 255, 240, 255},
	"hotpink":              {255, 105, 180, 255},
	"indianred":            {205, 92, 92, 255},
	"indigo":               {75, 0, 130, 255},
	"ivory":                {255, 255, 240, 255},
	"khaki":                {240, 230, 140, 255},
	"lavender":             {230, 230, 250, 255},
	"lavenderblush":        {255, 240, 245, 255},
	"lawngreen":            {124, 252, 0, 255},
	"lemonchiffon":         {255, 250, 205, 255},
	"lightblue":            {173, 216, 230, 255},
	"lightcoral":           {240, 128, 128, 255},
	"lightcyan":            {224, 255, 255, 255},
	"lightgoldenrodyellow": {250, 250, 210, 255},
	"lightgray":            {211, 211, 211, 255},
	"lightgreen":           {144, 238, 144, 255},
	"lightgrey":            {211, 211, 211, 255},
	"lightpink":            {255, 182, 193, 255},
	"lightsalmon":          {255, 160, 122, 255},
	"lightseagreen":        {32, 178, 170, 255},
	"lightskyblue":         {135, 206, 250, 255},
	"lightslategray":       {119, 136, 153, 255},
	"lightslategrey":       {119, 136, 153, 255},
	"lightsteelblue":       {176, 196, 222, 255},
	"lightyellow":          {255, 255, 224, 255},
	"lime":                 {0, 255, 0, 255},
	"limegreen":            {50, 205, 50, 255},
	"linen":                {250, 240, 230, 255},
	"magenta":              {255, 0, 255, 255},
	"maroon":               {128, 0, 0, 255},
	"mediumaquamarine":     {102, 205, 170, 255},
	"mediumblue":           {0, 0, 205, 255},
	"mediumorchid":         {186, 85, 211, 255},
	"mediumpurple":         {147, 112, 219, 255},
	"mediumseagreen":       {60, 179, 113, 255},
	"mediumslateblue":      {123, 104, 238, 255},
	"mediumspringgreen":    {0, 250, 154, 255},
	"mediumturquoise":      {72, 209, 204, 255},
	"mediumvioletred":      {199, 21, 133, 255},
	"midnightblue":         {25, 25, 112, 255},
	"mintcream":            {245, 255, 250, 255},
	"mistyrose":            {255, 228, 225, 255},
	"moccasin":             {255, 228, 181, 255},
	"navajowhite":          {255, 222, 173, 255},
	"navy":                 {0, 0, 128, 255},
	"oldlace":              {253, 245, 230, 255},
	"olive":                {128, 128, 0, 255},
	"olivedrab":            {107, 142, 35, 255},
	"orange":               {255, 165, 0, 255},
	"orangered":            {255, 69, 0, 255},
	"orchid":               {218, 112, 214, 255},
	"palegoldenrod":        {238, 232, 170, 255},
	"palegreen":            {152, 251, 152, 255},
	"paleturquoise":        {175, 238, 238, 255},
	"palevioletred":        {219, 112, 147, 255},
	"papayawhip":           {255, 239, 213, 255},
	"peachpuff":            {255, 218, 185, 255},
	"peru":                 {205, 133, 63, 255},
	"pink":                 {255, 192, 203, 255},
	"plum":                 {221, 160, 221, 255},
	"powderblue":           {176, 224, 230, 255},
	"purple":               {128, 0, 128, 255},
	"rebeccapurple":        {102, 51, 153, 255},
	"red":                  {255, 0, 0, 255},
	"rosybrown":            {188, 143, 143, 255},
	"royalblue":            {65, 105, 225, 255},
	"saddlebrown":          {139, 69, 19, 255},
	"salmon":               {250, 128, 114, 255},
	"sandybrown":           {244, 164, 96, 255},
	"seagreen":             {46, 139, 87, 255},
	"seashell":             {255, 245, 238, 255},
	"sienna":               {160, 82, 45, 255},
	"silver":               {192, 192, 192, 255},
	"skyblue":              {135, 206, 235, 255},
	"slateblue":            {106, 90, 205, 255},
	"slategray":            {112, 128, 144, 255},
	"slategrey":            {112, 128, 144, 255},
	"snow":                 {255, 250, 250, 255},
	"springgreen":          {0, 255, 127, 255},
	"steelblue":            {70, 130, 180, 255},
	"tan":                  {210, 180, 140, 255},
	"teal":                 {0, 128, 128, 255},
	"thistle":              {216, 191, 216, 255},
	"tomato":               {255, 99, 71, 255},
	"turquoise":            {64, 224, 208, 255},
	"violet":               {238, 130, 238, 255},
	"wheat":                {245, 222, 179, 255},
	"white":                {255, 255, 255, 255},
	"whitesmoke":           {245, 245, 245, 255},
	"yellow":               {255, 255, 0, 255},
	"yellowgreen":          {154, 205, 50, 255},
}
