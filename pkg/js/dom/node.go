package dom

import (
	"strings"
	"sync"
)

// NodeType represents the type of a DOM node.
type NodeType int

const (
	DocumentNode NodeType = iota
	ElementNode
	TextNode
	CommentNode
	DoctypeNode
)

// Node represents a single node in the DOM tree.
type Node struct {
	Type      NodeType
	Tag       string            // lowercase tag name (elements only)
	Namespace string            // namespace URI if any
	Attrs     map[string]string // element attributes
	Text      string            // text/comment content
	Children  []*Node
	Parent    *Node
	Events    *EventTarget      // event listeners

	// Cached lookups
	id        string   // cached id attr
	classList []string // cached class list
}

// Document is the root container of a parsed DOM tree.
type Document struct {
	Root        *Node
	DocType     string
	URL         string
	Cookies     *CookieJar
	Storage     *Storage
	TempFiles   *TempStore
	Images      *ImageCache
	ViewportW   int // screenshot viewport width (default 1280)
	ViewportH   int // screenshot viewport height (default 720)
	mu          sync.Mutex
}

// NewDocument creates a new empty Document.
func NewDocument(url string) *Document {
	return &Document{
		Root: &Node{
			Type:     DocumentNode,
			Tag:      "#document",
			Children: make([]*Node, 0),
			Attrs:    make(map[string]string),
		},
		URL:       url,
		Cookies:   NewCookieJar(),
		Storage:   NewStorage(),
		TempFiles: NewTempStore(""),
		Images:    NewImageCache(),
		ViewportW: 1280,
		ViewportH: 720,
	}
}

// NewElement creates a new element node.
func NewElement(tag string) *Node {
	return &Node{
		Type:     ElementNode,
		Tag:      strings.ToLower(tag),
		Attrs:    make(map[string]string),
		Children: make([]*Node, 0),
	}
}

// NewTextNode creates a text node.
func NewTextNode(text string) *Node {
	return &Node{
		Type: TextNode,
		Text: text,
	}
}

// NewComment creates a comment node.
func NewComment(text string) *Node {
	return &Node{
		Type: CommentNode,
		Text: text,
	}
}

// ──────────────────────────────────────────────
// Attribute helpers
// ──────────────────────────────────────────────

// GetAttribute returns an attribute value or empty string.
func (n *Node) GetAttribute(key string) string {
	if n.Attrs == nil {
		return ""
	}
	return n.Attrs[strings.ToLower(key)]
}

// SetAttribute sets an attribute, updating caches.
func (n *Node) SetAttribute(key, value string) {
	if n.Attrs == nil {
		n.Attrs = make(map[string]string)
	}
	k := strings.ToLower(key)
	n.Attrs[k] = value
	if k == "id" {
		n.id = value
	}
	if k == "class" {
		n.classList = splitClasses(value)
	}
}

// RemoveAttribute removes an attribute.
func (n *Node) RemoveAttribute(key string) {
	k := strings.ToLower(key)
	delete(n.Attrs, k)
	if k == "id" {
		n.id = ""
	}
	if k == "class" {
		n.classList = nil
	}
}

// HasAttribute checks if an attribute exists.
func (n *Node) HasAttribute(key string) bool {
	_, ok := n.Attrs[strings.ToLower(key)]
	return ok
}

// ID returns the cached id attribute.
func (n *Node) ID() string {
	if n.id == "" && n.Attrs != nil {
		n.id = n.Attrs["id"]
	}
	return n.id
}

// ClassList returns the cached class list.
func (n *Node) ClassList() []string {
	if n.classList == nil && n.Attrs != nil {
		n.classList = splitClasses(n.Attrs["class"])
	}
	return n.classList
}

// HasClass checks if the element has a specific class.
func (n *Node) HasClass(cls string) bool {
	for _, c := range n.ClassList() {
		if c == cls {
			return true
		}
	}
	return false
}

// AddClass adds a CSS class to the element.
func (n *Node) AddClass(cls string) {
	if n.HasClass(cls) {
		return
	}
	current := n.GetAttribute("class")
	if current == "" {
		n.SetAttribute("class", cls)
	} else {
		n.SetAttribute("class", current+" "+cls)
	}
	n.classList = nil // invalidate cache
}

// RemoveClass removes a CSS class from the element.
func (n *Node) RemoveClass(cls string) {
	classes := n.ClassList()
	var result []string
	for _, c := range classes {
		if c != cls {
			result = append(result, c)
		}
	}
	n.SetAttribute("class", strings.Join(result, " "))
	n.classList = nil // invalidate cache
}

// ──────────────────────────────────────────────
// Tree manipulation
// ──────────────────────────────────────────────

// AppendChild adds a child node.
func (n *Node) AppendChild(child *Node) {
	if child.Parent != nil {
		child.Parent.RemoveChild(child)
	}
	child.Parent = n
	n.Children = append(n.Children, child)
}

// PrependChild adds a child at position 0.
func (n *Node) PrependChild(child *Node) {
	if child.Parent != nil {
		child.Parent.RemoveChild(child)
	}
	child.Parent = n
	n.Children = append([]*Node{child}, n.Children...)
}

// InsertBefore inserts newChild before refChild.
func (n *Node) InsertBefore(newChild, refChild *Node) {
	if newChild.Parent != nil {
		newChild.Parent.RemoveChild(newChild)
	}
	newChild.Parent = n
	for i, c := range n.Children {
		if c == refChild {
			rear := make([]*Node, len(n.Children[i:]))
			copy(rear, n.Children[i:])
			n.Children = append(n.Children[:i], newChild)
			n.Children = append(n.Children, rear...)
			return
		}
	}
	// refChild not found, append
	n.Children = append(n.Children, newChild)
}

// RemoveChild removes a child node.
func (n *Node) RemoveChild(child *Node) {
	for i, c := range n.Children {
		if c == child {
			child.Parent = nil
			n.Children = append(n.Children[:i], n.Children[i+1:]...)
			return
		}
	}
}

// Remove detaches this node from its parent.
func (n *Node) Remove() {
	if n.Parent != nil {
		n.Parent.RemoveChild(n)
	}
}

// ReplaceChild replaces oldChild with newChild.
func (n *Node) ReplaceChild(newChild, oldChild *Node) {
	for i, c := range n.Children {
		if c == oldChild {
			if newChild.Parent != nil {
				newChild.Parent.RemoveChild(newChild)
			}
			oldChild.Parent = nil
			newChild.Parent = n
			n.Children[i] = newChild
			return
		}
	}
}

// Clone creates a copy of the node. If deep, also clones all children recursively.
func (n *Node) Clone(deep bool) *Node {
	clone := &Node{
		Type:      n.Type,
		Tag:       n.Tag,
		Namespace: n.Namespace,
		Text:      n.Text,
		Attrs:     make(map[string]string),
	}
	for k, v := range n.Attrs {
		clone.Attrs[k] = v
	}
	clone.id = n.id
	if n.classList != nil {
		clone.classList = make([]string, len(n.classList))
		copy(clone.classList, n.classList)
	}
	if deep {
		clone.Children = make([]*Node, 0, len(n.Children))
		for _, child := range n.Children {
			cc := child.Clone(true)
			cc.Parent = clone
			clone.Children = append(clone.Children, cc)
		}
	} else {
		clone.Children = make([]*Node, 0)
	}
	return clone
}

// ──────────────────────────────────────────────
// Traversal helpers
// ──────────────────────────────────────────────

// TextContent returns the concatenated text of all descendant text nodes.
func (n *Node) TextContent() string {
	var sb strings.Builder
	n.collectText(&sb)
	return sb.String()
}

func (n *Node) collectText(sb *strings.Builder) {
	if n.Type == TextNode {
		sb.WriteString(n.Text)
		return
	}
	for _, child := range n.Children {
		child.collectText(sb)
	}
}

// GetElementByID traverses descendants for the first element with matching id.
func (n *Node) GetElementByID(id string) *Node {
	if n.Type == ElementNode && n.ID() == id {
		return n
	}
	for _, child := range n.Children {
		if found := child.GetElementByID(id); found != nil {
			return found
		}
	}
	return nil
}

// GetElementsByTagName returns all descendant elements with the given tag.
func (n *Node) GetElementsByTagName(tag string) []*Node {
	tag = strings.ToLower(tag)
	var result []*Node
	n.walkElements(func(el *Node) bool {
		if tag == "*" || el.Tag == tag {
			result = append(result, el)
		}
		return false
	})
	return result
}

// GetElementsByClassName returns all descendant elements that have all specified classes.
func (n *Node) GetElementsByClassName(classes string) []*Node {
	cls := splitClasses(classes)
	if len(cls) == 0 {
		return nil
	}
	var result []*Node
	n.walkElements(func(el *Node) bool {
		for _, c := range cls {
			if !el.HasClass(c) {
				return false
			}
		}
		result = append(result, el)
		return false
	})
	return result
}

// QuerySelector returns the first element matching the CSS selector.
func (n *Node) QuerySelector(sel string) *Node {
	s, err := ParseSelector(sel)
	if err != nil {
		return nil
	}
	return s.QueryFirst(n)
}

// QuerySelectorAll returns all elements matching the CSS selector.
func (n *Node) QuerySelectorAll(sel string) []*Node {
	s, err := ParseSelector(sel)
	if err != nil {
		return nil
	}
	return s.QueryAll(n)
}

// walkElements visits all descendant element nodes via DFS.
// The callback can return true to stop early.
func (n *Node) walkElements(fn func(*Node) bool) bool {
	for _, child := range n.Children {
		if child.Type == ElementNode {
			if fn(child) {
				return true
			}
			if child.walkElements(fn) {
				return true
			}
		}
	}
	return false
}

// PreviousSibling returns the previous sibling node, or nil.
func (n *Node) PreviousSibling() *Node {
	if n.Parent == nil {
		return nil
	}
	for i, c := range n.Parent.Children {
		if c == n && i > 0 {
			return n.Parent.Children[i-1]
		}
	}
	return nil
}

// NextSibling returns the next sibling node, or nil.
func (n *Node) NextSibling() *Node {
	if n.Parent == nil {
		return nil
	}
	for i, c := range n.Parent.Children {
		if c == n && i < len(n.Parent.Children)-1 {
			return n.Parent.Children[i+1]
		}
	}
	return nil
}

// PreviousElementSibling returns the previous sibling that is an element.
func (n *Node) PreviousElementSibling() *Node {
	if n.Parent == nil {
		return nil
	}
	found := false
	for i := len(n.Parent.Children) - 1; i >= 0; i-- {
		c := n.Parent.Children[i]
		if c == n {
			found = true
			continue
		}
		if found && c.Type == ElementNode {
			return c
		}
	}
	return nil
}

// NextElementSibling returns the next sibling that is an element.
func (n *Node) NextElementSibling() *Node {
	if n.Parent == nil {
		return nil
	}
	found := false
	for _, c := range n.Parent.Children {
		if c == n {
			found = true
			continue
		}
		if found && c.Type == ElementNode {
			return c
		}
	}
	return nil
}

// ChildElementCount returns the number of child elements.
func (n *Node) ChildElementCount() int {
	count := 0
	for _, c := range n.Children {
		if c.Type == ElementNode {
			count++
		}
	}
	return count
}

// ChildElements returns only child elements (no text/comment nodes).
func (n *Node) ChildElements() []*Node {
	var result []*Node
	for _, c := range n.Children {
		if c.Type == ElementNode {
			result = append(result, c)
		}
	}
	return result
}

// ──────────────────────────────────────────────
// Document convenience methods
// ──────────────────────────────────────────────

// Body returns the <body> element, or nil.
func (d *Document) Body() *Node {
	return d.findTag("body")
}

// Head returns the <head> element, or nil.
func (d *Document) Head() *Node {
	return d.findTag("head")
}

// Title returns the text content of the <title> element.
func (d *Document) Title() string {
	if h := d.Head(); h != nil {
		for _, c := range h.Children {
			if c.Type == ElementNode && c.Tag == "title" {
				return c.TextContent()
			}
		}
	}
	return ""
}

// QuerySelector delegates to root.
func (d *Document) QuerySelector(sel string) *Node {
	return d.Root.QuerySelector(sel)
}

// QuerySelectorAll delegates to root.
func (d *Document) QuerySelectorAll(sel string) []*Node {
	return d.Root.QuerySelectorAll(sel)
}

// GetElementByID delegates to root.
func (d *Document) GetElementByID(id string) *Node {
	return d.Root.GetElementByID(id)
}

func (d *Document) findTag(tag string) *Node {
	var found *Node
	d.Root.walkElements(func(el *Node) bool {
		if el.Tag == tag {
			found = el
			return true
		}
		return false
	})
	return found
}

// ──────────────────────────────────────────────
// Utilities
// ──────────────────────────────────────────────

func splitClasses(s string) []string {
	if s == "" {
		return nil
	}
	fields := strings.Fields(s)
	result := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			result = append(result, f)
		}
	}
	return result
}
