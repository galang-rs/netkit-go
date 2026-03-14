package dom

import (
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Parse parses an HTML string into a Document.
func Parse(htmlStr string) (*Document, error) {
	doc := NewDocument("")
	root, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return nil, err
	}
	convertTree(root, doc.Root)

	// Extract doctype
	for _, child := range doc.Root.Children {
		if child.Type == DoctypeNode {
			doc.DocType = child.Text
			break
		}
	}

	return doc, nil
}

// ParseWithURL parses HTML and sets the document URL.
func ParseWithURL(htmlStr, url string) (*Document, error) {
	doc, err := Parse(htmlStr)
	if err != nil {
		return nil, err
	}
	doc.URL = url
	return doc, nil
}

// ParseFragment parses an HTML fragment and returns the resulting nodes.
// Useful for innerHTML assignment.
func ParseFragment(htmlStr string) ([]*Node, error) {
	// Parse as fragment within a <body> context
	ctx := &html.Node{
		Type:     html.ElementNode,
		DataAtom: atom.Body,
		Data:     "body",
	}
	nodes, err := html.ParseFragment(strings.NewReader(htmlStr), ctx)
	if err != nil {
		return nil, err
	}
	var result []*Node
	for _, n := range nodes {
		converted := convertNode(n)
		if converted != nil {
			convertChildren(n, converted)
			result = append(result, converted)
		}
	}
	return result, nil
}

// convertTree recursively converts golang.org/x/net/html nodes to our DOM nodes.
func convertTree(src *html.Node, dst *Node) {
	for child := src.FirstChild; child != nil; child = child.NextSibling {
		node := convertNode(child)
		if node == nil {
			continue
		}
		node.Parent = dst
		dst.Children = append(dst.Children, node)
		convertChildren(child, node)
	}
}

// convertChildren recursively converts children of an html.Node.
func convertChildren(src *html.Node, dst *Node) {
	for child := src.FirstChild; child != nil; child = child.NextSibling {
		node := convertNode(child)
		if node == nil {
			continue
		}
		node.Parent = dst
		dst.Children = append(dst.Children, node)
		convertChildren(child, node)
	}
}

// convertNode converts a single html.Node to our Node type.
func convertNode(n *html.Node) *Node {
	switch n.Type {
	case html.ElementNode:
		el := NewElement(n.Data)
		for _, attr := range n.Attr {
			el.SetAttribute(attr.Key, attr.Val)
		}
		if n.Namespace != "" {
			el.Namespace = n.Namespace
		}
		return el

	case html.TextNode:
		return NewTextNode(n.Data)

	case html.CommentNode:
		return NewComment(n.Data)

	case html.DoctypeNode:
		node := &Node{
			Type: DoctypeNode,
			Tag:  "!DOCTYPE",
			Text: n.Data,
			Attrs: make(map[string]string),
			Children: make([]*Node, 0),
		}
		for _, attr := range n.Attr {
			node.Attrs[attr.Key] = attr.Val
		}
		return node

	case html.DocumentNode:
		// Skip document node itself, process children
		return nil
	}
	return nil
}
