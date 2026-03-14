package dom

import (
	"strings"
)

// voidElements are HTML elements that cannot have children.
var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true,
	"embed": true, "hr": true, "img": true, "input": true,
	"link": true, "meta": true, "param": true, "source": true,
	"track": true, "wbr": true,
}

// rawTextElements contain raw text (no HTML parsing inside).
var rawTextElements = map[string]bool{
	"script": true, "style": true, "textarea": true, "title": true,
}

// Serialize converts a Document to an HTML string.
func Serialize(doc *Document) string {
	var sb strings.Builder
	if doc.DocType != "" {
		sb.WriteString("<!DOCTYPE ")
		sb.WriteString(doc.DocType)
		sb.WriteString(">")
	}
	for _, child := range doc.Root.Children {
		if child.Type == DoctypeNode {
			if doc.DocType == "" {
				sb.WriteString("<!DOCTYPE ")
				sb.WriteString(child.Text)
				sb.WriteString(">")
			}
			continue
		}
		serializeNode(&sb, child)
	}
	return sb.String()
}

// SerializeNode serializes a single node (outerHTML equivalent).
func SerializeNode(node *Node) string {
	var sb strings.Builder
	serializeNode(&sb, node)
	return sb.String()
}

// SerializeChildren serializes only the children (innerHTML equivalent).
func SerializeChildren(node *Node) string {
	var sb strings.Builder
	for _, child := range node.Children {
		serializeNode(&sb, child)
	}
	return sb.String()
}

func serializeNode(sb *strings.Builder, n *Node) {
	switch n.Type {
	case ElementNode:
		serializeElement(sb, n)
	case TextNode:
		sb.WriteString(n.Text)
	case CommentNode:
		sb.WriteString("<!--")
		sb.WriteString(n.Text)
		sb.WriteString("-->")
	case DoctypeNode:
		sb.WriteString("<!DOCTYPE ")
		sb.WriteString(n.Text)
		sb.WriteString(">")
	}
}

func serializeElement(sb *strings.Builder, n *Node) {
	sb.WriteByte('<')
	sb.WriteString(n.Tag)

	// Write attributes in a deterministic order: id first, class second, rest alphabetical
	if id := n.GetAttribute("id"); id != "" {
		sb.WriteString(` id="`)
		sb.WriteString(escapeAttr(id))
		sb.WriteByte('"')
	}
	if cls := n.GetAttribute("class"); cls != "" {
		sb.WriteString(` class="`)
		sb.WriteString(escapeAttr(cls))
		sb.WriteByte('"')
	}

	// Collect remaining attrs
	for k, v := range n.Attrs {
		if k == "id" || k == "class" {
			continue
		}
		sb.WriteByte(' ')
		sb.WriteString(k)
		sb.WriteString(`="`)
		sb.WriteString(escapeAttr(v))
		sb.WriteByte('"')
	}

	// Void elements: self-closing, no children
	if voidElements[n.Tag] {
		sb.WriteByte('>')
		return
	}

	sb.WriteByte('>')

	// Children
	for _, child := range n.Children {
		serializeNode(sb, child)
	}

	// Closing tag
	sb.WriteString("</")
	sb.WriteString(n.Tag)
	sb.WriteByte('>')
}

func escapeAttr(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
