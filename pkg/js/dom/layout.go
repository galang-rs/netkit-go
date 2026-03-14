package dom

import (
	"strconv"
	"strings"
)

// LayoutBox represents a laid-out element with computed position and size.
type LayoutBox struct {
	Node   *Node
	Style  *ComputedStyle
	X, Y   int // position relative to viewport (absolute)
	Width  int // content width
	Height int // content height (may be computed from children)

	// Box model edges
	PaddingTop, PaddingRight, PaddingBottom, PaddingLeft int
	MarginTop, MarginRight, MarginBottom, MarginLeft     int
	BorderTop, BorderRight, BorderBottom, BorderLeft     int

	Children []*LayoutBox

	// Text content for text-level boxes
	Text     string
	IsText   bool
	FontSize int // effective font size for this box

	// Image content
	IsImage  bool
	ImageSrc string // resolved image URL
}

// LayoutResult contains the full layout tree plus page dimensions.
type LayoutResult struct {
	Root           *LayoutBox
	ViewportWidth  int
	ViewportHeight int
	ContentHeight  int // total height of all content (scrollable)
	BodyBg         ComputedStyle // body background + color for full-page fill
}

// Layout computes positions and sizes for all visible elements.
func Layout(doc *Document, viewportWidth, viewportHeight int) *LayoutResult {
	sheet := CollectStyles(doc)

	root := &LayoutBox{
		Node:  doc.Root,
		Style: DefaultStyle("html"),
		Width: viewportWidth,
	}

	// Resolve body style for page background
	bodyStyle := DefaultStyle("body")
	if bodyNode := doc.Body(); bodyNode != nil {
		bodyStyle = ResolveStyle(bodyNode, sheet)
	}

	// Find <html> or start from root
	htmlNode := doc.findTag("html")
	if htmlNode == nil {
		htmlNode = doc.Root
	}

	// Layout recursively with inherited styles
	cursorY := 0
	layoutNode(htmlNode, root, sheet, viewportWidth, &cursorY, nil)

	// Content height = the farthest Y reached
	contentHeight := cursorY
	if contentHeight < viewportHeight {
		contentHeight = viewportHeight
	}
	root.Height = contentHeight

	return &LayoutResult{
		Root:           root,
		ViewportWidth:  viewportWidth,
		ViewportHeight: viewportHeight,
		ContentHeight:  contentHeight,
		BodyBg:         *bodyStyle,
	}
}

// inheritedStyle creates a child style inheriting text properties from parent.
func inheritedStyle(child *ComputedStyle, parent *ComputedStyle) *ComputedStyle {
	if parent == nil {
		return child
	}
	// Inherit text color if child has default (black)
	if child.Color == (DefaultStyle("").Color) && parent.Color != child.Color {
		child.Color = parent.Color
	}
	// Inherit font-size if default
	if child.FontSize == 16 && parent.FontSize != 16 {
		child.FontSize = parent.FontSize
	}
	// Inherit font-weight if default
	if child.FontWeight == 400 && parent.FontWeight != 400 {
		child.FontWeight = parent.FontWeight
	}
	// Inherit text-align
	if child.TextAlign == "left" && parent.TextAlign != "left" {
		child.TextAlign = parent.TextAlign
	}
	// Inherit line-height
	if child.LineHeight == 0 && parent.LineHeight > 0 {
		child.LineHeight = parent.LineHeight
	}
	return child
}

func layoutNode(node *Node, parentBox *LayoutBox, sheet *Stylesheet, availWidth int, cursorY *int, parentStyle *ComputedStyle) {
	for _, child := range node.Children {
		switch child.Type {
		case ElementNode:
			style := ResolveStyle(child, sheet)
			style = inheritedStyle(style, parentStyle)

			// Skip hidden elements
			if style.Display == "none" {
				continue
			}

			box := &LayoutBox{
				Node:          child,
				Style:         style,
				PaddingTop:    style.PaddingTop,
				PaddingRight:  style.PaddingRight,
				PaddingBottom: style.PaddingBottom,
				PaddingLeft:   style.PaddingLeft,
				MarginTop:     style.MarginTop,
				MarginRight:   style.MarginRight,
				MarginBottom:  style.MarginBottom,
				MarginLeft:    style.MarginLeft,
				BorderTop:     style.BorderTop,
				BorderRight:   style.BorderRight,
				BorderBottom:  style.BorderBottom,
				BorderLeft:    style.BorderLeft,
				FontSize:      style.FontSize,
			}

			isBlock := style.Display == "block" || style.Display == "list-item"

			// Handle <img> elements
			if child.Tag == "img" {
				src := child.GetAttribute("src")
				box.IsImage = true
				box.ImageSrc = src // raw src; resolved later in render with doc.URL

				// Image dimensions from attributes or CSS or defaults
				imgW := attrPx(child, "width", 0)
				imgH := attrPx(child, "height", 0)
				if style.Width > 0 {
					imgW = style.Width
				}
				if style.Height > 0 {
					imgH = style.Height
				}
				if imgW == 0 {
					imgW = 300
				}
				if imgH == 0 {
					imgH = 150
				}
				// Cap image width to available width
				if imgW > availWidth-box.MarginLeft-box.MarginRight {
					ratio := float64(imgH) / float64(imgW)
					imgW = availWidth - box.MarginLeft - box.MarginRight
					imgH = int(float64(imgW) * ratio)
				}
				box.Width = imgW
				box.Height = imgH
				box.X = parentBox.X + parentBox.PaddingLeft + box.MarginLeft
				box.Y = *cursorY + box.MarginTop
				*cursorY = box.Y + box.Height + box.MarginBottom
				parentBox.Children = append(parentBox.Children, box)
				continue
			}

			// Handle <br> as line break
			if child.Tag == "br" {
				lh := lineHeightFromStyle(style)
				*cursorY += lh
				continue
			}

			if isBlock {
				// ── Block element ──
				// Margin collapsing: top margin collapses with previous bottom margin
				*cursorY += box.MarginTop

				box.X = parentBox.X + parentBox.PaddingLeft + box.MarginLeft + box.BorderLeft
				box.Y = *cursorY

				// Content width = parent content - own horizontal edges
				totalHoriz := box.MarginLeft + box.BorderLeft + box.PaddingLeft +
					box.PaddingRight + box.BorderRight + box.MarginRight
				contentWidth := availWidth - totalHoriz
				if contentWidth < 0 {
					contentWidth = 0
				}
				if style.Width > 0 && style.Width < contentWidth {
					contentWidth = style.Width
				}
				box.Width = contentWidth

				// Inner cursor starts after border + padding
				innerY := box.Y + box.PaddingTop
				savedY := innerY

				// Recurse into children
				layoutNode(child, box, sheet, contentWidth, &innerY, style)

				// Compute height
				childrenHeight := innerY - savedY
				if style.Height > 0 {
					box.Height = style.Height
				} else {
					box.Height = childrenHeight + box.PaddingTop + box.PaddingBottom
				}

				// Add border to total height
				totalHeight := box.Height + box.BorderTop + box.BorderBottom
				*cursorY = box.Y + totalHeight + box.MarginBottom

			} else {
				// ── Inline element ──
				box.X = parentBox.X + parentBox.PaddingLeft
				box.Y = *cursorY

				innerY := *cursorY
				layoutNode(child, box, sheet, availWidth, &innerY, style)

				if style.Height > 0 {
					box.Height = style.Height
				} else {
					textHeight := innerY - *cursorY
					if textHeight == 0 {
						textHeight = lineHeightFromStyle(style)
					}
					box.Height = textHeight
				}
				if style.Width > 0 {
					box.Width = style.Width
				} else {
					box.Width = availWidth - parentBox.PaddingLeft - parentBox.PaddingRight
				}

				*cursorY = innerY
			}

			parentBox.Children = append(parentBox.Children, box)

		case TextNode:
			text := child.Text
			if strings.TrimSpace(text) == "" {
				continue
			}

			// Inherit style from parent
			textStyle := parentStyle
			if textStyle == nil {
				textStyle = parentBox.Style
			}
			if textStyle == nil {
				textStyle = DefaultStyle("")
			}

			fontSize := textStyle.FontSize
			if fontSize == 0 {
				fontSize = 16
			}
			lh := lineHeightFromStyle(textStyle)

			// Content width for wrapping
			textWidth := availWidth - parentBox.PaddingLeft - parentBox.PaddingRight
			if textWidth <= 0 {
				textWidth = availWidth
			}
			if textWidth <= 0 {
				textWidth = 100
			}

			lines := wrapText(text, textWidth, fontSize)
			textHeight := len(lines) * lh

			textBox := &LayoutBox{
				Node:     child,
				Style:    textStyle,
				X:        parentBox.X + parentBox.PaddingLeft,
				Y:        *cursorY,
				Width:    textWidth,
				Height:   textHeight,
				IsText:   true,
				Text:     text,
				FontSize: fontSize,
			}

			parentBox.Children = append(parentBox.Children, textBox)
			*cursorY += textHeight
		}
	}
}

func attrPx(n *Node, attr string, fallback int) int {
	val := n.GetAttribute(attr)
	if val == "" {
		return fallback
	}
	val = strings.TrimSpace(val)
	val = strings.TrimSuffix(val, "px")
	if v, err := strconv.Atoi(val); err == nil {
		return v
	}
	return fallback
}

func lineHeightFromStyle(style *ComputedStyle) int {
	if style == nil {
		return 20
	}
	if style.LineHeight > 0 {
		return style.LineHeight
	}
	lh := int(float64(style.FontSize) * 1.4)
	if lh < 10 {
		lh = 20
	}
	return lh
}

// wrapText splits text into lines based on available width and character width.
func wrapText(text string, maxWidth, fontSize int) []string {
	charWidth := int(float64(fontSize) * 0.6)
	if charWidth < 1 {
		charWidth = 1
	}
	charsPerLine := maxWidth / charWidth
	if charsPerLine < 1 {
		charsPerLine = 1
	}

	text = strings.ReplaceAll(text, "\r\n", "\n")
	paragraphs := strings.Split(text, "\n")

	var lines []string
	for _, para := range paragraphs {
		para = strings.TrimSpace(para)
		if para == "" {
			lines = append(lines, "")
			continue
		}
		words := strings.Fields(para)
		var line strings.Builder
		lineLen := 0
		for _, word := range words {
			wl := len(word)
			if lineLen > 0 && lineLen+1+wl > charsPerLine {
				lines = append(lines, line.String())
				line.Reset()
				lineLen = 0
			}
			if lineLen > 0 {
				line.WriteByte(' ')
				lineLen++
			}
			line.WriteString(word)
			lineLen += wl
		}
		if line.Len() > 0 {
			lines = append(lines, line.String())
		}
	}

	if len(lines) == 0 {
		lines = append(lines, text)
	}
	return lines
}

// FindBoxByNode searches the layout tree for a box matching the given node.
func FindBoxByNode(root *LayoutBox, target *Node) *LayoutBox {
	if root.Node == target {
		return root
	}
	for _, child := range root.Children {
		if found := FindBoxByNode(child, target); found != nil {
			return found
		}
	}
	return nil
}
