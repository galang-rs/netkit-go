package dom

import (
	"strconv"
	"strings"

	"github.com/dop251/goja"
)

// WrapNode creates a JS-accessible object that implements the W3C Element/Node interface.
// Uses NodeCache to return the same goja.Object for the same *Node, so React expando
// properties (like __reactFiber$, __reactEvents$) persist across accesses.
func (env *BrowserEnv) WrapNode(n *Node) interface{} {
	if n == nil {
		return nil
	}

	// Cache: return existing wrapper so React expando properties persist
	if cached, ok := env.NodeCache[n]; ok {
		return cached
	}

	vm := env.VM

	// Lazy init events
	if n.Events == nil {
		n.Events = NewEventTarget()
	}

	obj := vm.NewObject()

	// ── Identity ──
	obj.Set("nodeType", nodeTypeNum(n))
	obj.Set("nodeName", nodeName(n))
	obj.Set("tagName", strings.ToUpper(n.Tag))
	obj.Set("localName", n.Tag)
	obj.Set("nodeValue", nodeValue(n))
	obj.Set("id", n.ID())
	obj.Set("className", strings.Join(n.ClassList(), " "))

	// ── Text content (getter/setter — React uses el.textContent = '' to clear nodes) ──
	obj.DefineAccessorProperty("textContent", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(n.TextContent())
	}), vm.ToValue(func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) > 0 {
			text := call.Arguments[0].String()
			// Clear all children and set text
			n.Children = n.Children[:0]
			if text != "" {
				textNode := &Node{Type: TextNode, Text: text, Attrs: make(map[string]string)}
				n.AppendChild(textNode)
			}
		}
		return goja.Undefined()
	}), goja.FLAG_FALSE, goja.FLAG_TRUE)

	obj.DefineAccessorProperty("innerText", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(n.TextContent())
	}), vm.ToValue(func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) > 0 {
			text := call.Arguments[0].String()
			n.Children = n.Children[:0]
			if text != "" {
				textNode := &Node{Type: TextNode, Text: text, Attrs: make(map[string]string)}
				n.AppendChild(textNode)
			}
		}
		return goja.Undefined()
	}), goja.FLAG_FALSE, goja.FLAG_TRUE)

	// ── innerHTML getter/setter (React reads and writes innerHTML) ──
	obj.DefineAccessorProperty("innerHTML", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(SerializeChildren(n))
	}), vm.ToValue(func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) > 0 {
			htmlStr := call.Arguments[0].String()
			n.Children = n.Children[:0]
			if htmlStr != "" {
				frags, err := ParseFragment(htmlStr)
				if err == nil {
					for _, f := range frags {
						n.AppendChild(f)
					}
				}
			}
		}
		return goja.Undefined()
	}), goja.FLAG_FALSE, goja.FLAG_TRUE)

	obj.DefineAccessorProperty("outerHTML", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(SerializeNode(n))
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)

	// ── Attribute methods ──
	obj.Set("getAttribute", func(key string) interface{} {
		if !n.HasAttribute(key) {
			return goja.Null()
		}
		return n.GetAttribute(key)
	})
	obj.Set("setAttribute", func(key, value string) {
		n.SetAttribute(key, value)
		if key == "id" {
			obj.Set("id", value)
		} else if key == "class" {
			obj.Set("className", value)
		}
	})
	obj.Set("removeAttribute", func(key string) {
		n.RemoveAttribute(key)
	})
	obj.Set("hasAttribute", func(key string) bool {
		return n.HasAttribute(key)
	})
	obj.Set("attributes", env.wrapAttributes(n))

	// ── Dataset (data-* attributes) ──
	obj.Set("dataset", env.wrapDataset(n))

	// ── Style ──
	obj.Set("style", env.wrapStyle(n))

	// ── ClassList ──
	obj.Set("classList", env.wrapClassList(n, obj))

	// ── Children (MUST be getters, not functions — React accesses as properties) ──
	obj.DefineAccessorProperty("childNodes", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(env.wrapNodeListLazy(n.Children))
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	obj.DefineAccessorProperty("children", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(env.wrapNodeListLazy(n.ChildElements()))
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	obj.DefineAccessorProperty("childElementCount", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(len(n.ChildElements()))
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)

	// ── DOM navigation properties (MUST be getters, not functions!) ──
	// React accesses these as properties: e.lastChild, e.firstChild, e.parentNode, etc.
	// If they're functions, `e.lastChild` returns the function (truthy), not the node.
	obj.DefineAccessorProperty("firstChild", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		if len(n.Children) > 0 {
			return vm.ToValue(env.WrapNode(n.Children[0]))
		}
		return goja.Null()
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)

	obj.DefineAccessorProperty("lastChild", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		if len(n.Children) > 0 {
			return vm.ToValue(env.WrapNode(n.Children[len(n.Children)-1]))
		}
		return goja.Null()
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)

	obj.DefineAccessorProperty("firstElementChild", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		for _, c := range n.Children {
			if c.Type == ElementNode {
				return vm.ToValue(env.WrapNode(c))
			}
		}
		return goja.Null()
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)

	obj.DefineAccessorProperty("lastElementChild", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		for i := len(n.Children) - 1; i >= 0; i-- {
			if n.Children[i].Type == ElementNode {
				return vm.ToValue(env.WrapNode(n.Children[i]))
			}
		}
		return goja.Null()
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)

	obj.DefineAccessorProperty("parentNode", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		if n.Parent == nil {
			return goja.Null()
		}
		return vm.ToValue(env.WrapNode(n.Parent))
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)

	obj.DefineAccessorProperty("parentElement", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		if n.Parent == nil || n.Parent.Type != ElementNode {
			return goja.Null()
		}
		return vm.ToValue(env.WrapNode(n.Parent))
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)

	obj.DefineAccessorProperty("nextSibling", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		s := n.NextSibling()
		if s == nil {
			return goja.Null()
		}
		return vm.ToValue(env.WrapNode(s))
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)

	obj.DefineAccessorProperty("previousSibling", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		s := n.PreviousSibling()
		if s == nil {
			return goja.Null()
		}
		return vm.ToValue(env.WrapNode(s))
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)

	obj.DefineAccessorProperty("nextElementSibling", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		s := n.NextElementSibling()
		if s == nil {
			return goja.Null()
		}
		return vm.ToValue(env.WrapNode(s))
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)

	obj.DefineAccessorProperty("previousElementSibling", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		s := n.PreviousElementSibling()
		if s == nil {
			return goja.Null()
		}
		return vm.ToValue(env.WrapNode(s))
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)

	// ── DOM Mutation ──
	obj.Set("appendChild", func(call goja.FunctionCall) goja.Value {
		child := env.unwrapNode(call.Arguments[0])
		if child != nil {
			// Remove from old parent
			if child.Parent != nil {
				child.Remove()
			}
			n.AppendChild(child)
		}
		return call.Arguments[0]
	})
	obj.Set("removeChild", func(call goja.FunctionCall) goja.Value {
		child := env.unwrapNode(call.Arguments[0])
		if child != nil {
			child.Remove()
		}
		return call.Arguments[0]
	})
	obj.Set("insertBefore", func(call goja.FunctionCall) goja.Value {
		newChild := env.unwrapNode(call.Arguments[0])
		var refChild *Node
		if len(call.Arguments) > 1 && !goja.IsNull(call.Arguments[1]) && !goja.IsUndefined(call.Arguments[1]) {
			refChild = env.unwrapNode(call.Arguments[1])
		}
		if newChild != nil {
			if newChild.Parent != nil {
				newChild.Remove()
			}
			if refChild != nil {
				n.InsertBefore(newChild, refChild)
			} else {
				n.AppendChild(newChild)
			}
		}
		return call.Arguments[0]
	})
	obj.Set("replaceChild", func(call goja.FunctionCall) goja.Value {
		newChild := env.unwrapNode(call.Arguments[0])
		oldChild := env.unwrapNode(call.Arguments[1])
		if newChild != nil && oldChild != nil {
			if newChild.Parent != nil {
				newChild.Remove()
			}
			n.InsertBefore(newChild, oldChild)
			oldChild.Remove()
		}
		if len(call.Arguments) > 1 {
			return call.Arguments[1]
		}
		return goja.Undefined()
	})
	obj.Set("cloneNode", func(deep bool) interface{} {
		clone := cloneNode(n, deep)
		return env.WrapNode(clone)
	})
	obj.Set("remove", func() {
		n.Remove()
	})
	obj.Set("contains", func(call goja.FunctionCall) goja.Value {
		other := env.unwrapNode(call.Arguments[0])
		if other == nil {
			return vm.ToValue(false)
		}
		return vm.ToValue(nodeContains(n, other))
	})
	obj.Set("hasChildNodes", func() bool {
		return len(n.Children) > 0
	})

	// ── innerHTML setter ──
	obj.Set("setInnerHTML", func(htmlStr string) {
		n.Children = n.Children[:0]
		frags, err := ParseFragment(htmlStr)
		if err == nil {
			for _, f := range frags {
				n.AppendChild(f)
			}
		}
	})

	// ── Query methods on element ──
	obj.Set("querySelector", func(sel string) interface{} {
		found := n.QuerySelector(sel)
		if found == nil {
			return goja.Null()
		}
		return env.WrapNode(found)
	})
	obj.Set("querySelectorAll", func(sel string) interface{} {
		nodes := n.QuerySelectorAll(sel)
		return env.wrapNodeList(nodes)
	})
	obj.Set("getElementsByTagName", func(tag string) interface{} {
		nodes := n.GetElementsByTagName(tag)
		return env.wrapNodeList(nodes)
	})
	obj.Set("getElementsByClassName", func(cls string) interface{} {
		sel := "." + strings.ReplaceAll(cls, " ", ".")
		nodes := n.QuerySelectorAll(sel)
		return env.wrapNodeList(nodes)
	})
	obj.Set("matches", func(sel string) bool {
		// Check via parent if available
		parent := n.Parent
		if parent != nil {
			matches := parent.QuerySelectorAll(sel)
			for _, m := range matches {
				if m == n {
					return true
				}
			}
			return false
		}
		// Fallback for detached elements: self-match by id/class/tag
		if n.Type != ElementNode {
			return false
		}
		sel = strings.TrimSpace(sel)
		if sel == "" {
			return false
		}
		if sel[0] == '#' {
			return n.ID() == sel[1:]
		}
		if sel[0] == '.' {
			for _, c := range n.ClassList() {
				if c == sel[1:] {
					return true
				}
			}
			return false
		}
		return strings.EqualFold(n.Tag, sel)
	})
	obj.Set("closest", func(sel string) interface{} {
		for cur := n; cur != nil; cur = cur.Parent {
			if cur.Type == ElementNode {
				parent := cur.Parent
				if parent != nil {
					matches := parent.QuerySelectorAll(sel)
					for _, m := range matches {
						if m == cur {
							return env.WrapNode(cur)
						}
					}
				}
			}
		}
		return goja.Null()
	})

	// ── Event methods ──
	obj.Set("addEventListener", func(eventType string, handler interface{}, opts ...interface{}) {
		n.Events.AddEventListener(eventType, handler)
	})
	obj.Set("removeEventListener", func(eventType string, handler interface{}) {
		n.Events.RemoveEventListener(eventType, handler)
	})
	obj.Set("dispatchEvent", func(call goja.FunctionCall) goja.Value {
		// Extract event type from the JS event object
		var eventType string
		var eventObj goja.Value
		if len(call.Arguments) > 0 {
			eventObj = call.Arguments[0]
			eObj := eventObj.ToObject(vm)
			if eObj != nil {
				typeVal := eObj.Get("type")
				if typeVal != nil && !goja.IsUndefined(typeVal) {
					eventType = typeVal.String()
				}
			}
		}
		if eventType == "" {
			return vm.ToValue(false)
		}
		// Fire all registered handlers
		handlers := n.Events.GetHandlers(eventType)
		for _, h := range handlers {
			if callable, ok := goja.AssertFunction(vm.ToValue(h)); ok {
				callable(goja.Undefined(), eventObj)
			}
		}
		return vm.ToValue(true)
	})

	// ── Geometry stubs (React needs these) ──
	obj.Set("getBoundingClientRect", func() interface{} {
		return map[string]interface{}{
			"top": 0, "right": 0, "bottom": 0, "left": 0,
			"width": 0, "height": 0, "x": 0, "y": 0,
		}
	})
	obj.Set("getClientRects", func() interface{} {
		return vm.NewArray()
	})
	obj.Set("offsetWidth", 0)
	obj.Set("offsetHeight", 0)
	obj.Set("offsetTop", 0)
	obj.Set("offsetLeft", 0)
	obj.Set("offsetParent", goja.Null())
	obj.Set("clientWidth", 0)
	obj.Set("clientHeight", 0)
	obj.Set("scrollWidth", 0)
	obj.Set("scrollHeight", 0)
	obj.Set("scrollTop", 0)
	obj.Set("scrollLeft", 0)

	// ── Focus/blur stubs ──
	obj.Set("focus", func() {})
	obj.Set("blur", func() {})
	obj.Set("click", func() {})
	obj.Set("scrollIntoView", func(opts ...interface{}) {})

	// ── Form element properties ──
	if n.HasAttribute("value") {
		obj.Set("value", n.GetAttribute("value"))
	} else {
		obj.Set("value", "")
	}
	obj.Set("checked", n.HasAttribute("checked"))
	obj.Set("disabled", n.HasAttribute("disabled"))
	obj.Set("type", n.GetAttribute("type"))
	obj.Set("name", n.GetAttribute("name"))
	obj.Set("src", n.GetAttribute("src"))
	obj.Set("href", n.GetAttribute("href"))

	// ── React-required properties ──
	obj.DefineAccessorProperty("ownerDocument", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		return vm.Get("document")
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	ns := n.Namespace
	if ns == "" && n.Type == ElementNode {
		ns = "http://www.w3.org/1999/xhtml"
	}
	obj.Set("namespaceURI", ns)

	// ── insertAdjacentHTML ──
	obj.Set("insertAdjacentHTML", func(position, htmlStr string) {
		frags, err := ParseFragment(htmlStr)
		if err != nil || len(frags) == 0 {
			return
		}
		switch strings.ToLower(position) {
		case "beforebegin":
			if n.Parent != nil {
				for _, f := range frags {
					n.Parent.InsertBefore(f, n)
				}
			}
		case "afterbegin":
			for i := len(frags) - 1; i >= 0; i-- {
				n.PrependChild(frags[i])
			}
		case "beforeend":
			for _, f := range frags {
				n.AppendChild(f)
			}
		case "afterend":
			if n.Parent != nil {
				next := n.NextSibling()
				for _, f := range frags {
					if next != nil {
						n.Parent.InsertBefore(f, next)
					} else {
						n.Parent.AppendChild(f)
					}
				}
			}
		}
	})

	// ── Attribute NS methods (React SVG) ──
	obj.Set("getAttributeNS", func(ns, name string) interface{} {
		if !n.HasAttribute(name) {
			return goja.Null()
		}
		return n.GetAttribute(name)
	})
	obj.Set("setAttributeNS", func(ns, name, value string) {
		n.SetAttribute(name, value)
	})
	obj.Set("removeAttributeNS", func(ns, name string) {
		n.RemoveAttribute(name)
	})
	obj.Set("hasAttributeNS", func(ns, name string) bool {
		return n.HasAttribute(name)
	})

	// Store back-reference for unwrapping
	obj.Set("__domNode__", n)

	// Cache: store for future lookups (React expando properties persist)
	env.NodeCache[n] = obj

	return obj
}

// ── Helper functions ──

func nodeTypeNum(n *Node) int {
	switch n.Type {
	case ElementNode:
		return 1
	case TextNode:
		return 3
	case CommentNode:
		return 8
	case DocumentNode:
		return 9
	case DoctypeNode:
		return 10
	}
	return 1
}

func nodeName(n *Node) string {
	switch n.Type {
	case TextNode:
		return "#text"
	case CommentNode:
		return "#comment"
	case DocumentNode:
		return "#document"
	default:
		return strings.ToUpper(n.Tag)
	}
}

func nodeValue(n *Node) interface{} {
	switch n.Type {
	case TextNode, CommentNode:
		return n.Text
	default:
		return nil
	}
}

func cloneNode(n *Node, deep bool) *Node {
	clone := &Node{
		Type:  n.Type,
		Tag:   n.Tag,
		Text:  n.Text,
		Attrs: make(map[string]string),
	}
	for k, v := range n.Attrs {
		clone.Attrs[k] = v
	}
	if deep {
		clone.Children = make([]*Node, 0, len(n.Children))
		for _, child := range n.Children {
			childClone := cloneNode(child, true)
			childClone.Parent = clone
			clone.Children = append(clone.Children, childClone)
		}
	} else {
		clone.Children = make([]*Node, 0)
	}
	return clone
}

func nodeContains(parent, target *Node) bool {
	if parent == target {
		return true
	}
	for _, child := range parent.Children {
		if nodeContains(child, target) {
			return true
		}
	}
	return false
}

func (env *BrowserEnv) wrapNodeList(nodes []*Node) interface{} {
	vm := env.VM
	arr := vm.NewArray()
	for i, node := range nodes {
		arr.Set(strconv.Itoa(i), env.WrapNode(node))
	}
	arr.Set("length", len(nodes))
	arr.Set("item", func(idx int) interface{} {
		if idx >= 0 && idx < len(nodes) {
			return env.WrapNode(nodes[idx])
		}
		return nil
	})
	arr.Set("forEach", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) > 0 {
			if fn, ok := goja.AssertFunction(call.Arguments[0]); ok {
				for i, node := range nodes {
					fn(goja.Undefined(), env.VM.ToValue(env.WrapNode(node)), env.VM.ToValue(i))
				}
			}
		}
		return goja.Undefined()
	})
	return arr
}

func (env *BrowserEnv) wrapAttributes(n *Node) interface{} {
	vm := env.VM
	obj := vm.NewObject()
	obj.Set("length", len(n.Attrs))
	i := 0
	for k, v := range n.Attrs {
		obj.Set(k, map[string]interface{}{"name": k, "value": v})
		obj.Set(strconv.Itoa(i), map[string]interface{}{"name": k, "value": v})
		i++
	}
	obj.Set("getNamedItem", func(name string) interface{} {
		if v, ok := n.Attrs[name]; ok {
			return map[string]interface{}{"name": name, "value": v}
		}
		return nil
	})
	return obj
}

func (env *BrowserEnv) wrapDataset(n *Node) interface{} {
	vm := env.VM
	obj := vm.NewObject()
	for k, v := range n.Attrs {
		if strings.HasPrefix(k, "data-") {
			camelKey := dataToCamel(k[5:])
			obj.Set(camelKey, v)
		}
	}
	return obj
}

func dataToCamel(s string) string {
	parts := strings.Split(s, "-")
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

func (env *BrowserEnv) wrapStyle(n *Node) interface{} {
	vm := env.VM
	obj := vm.NewObject()

	// Parse existing inline style
	styleStr := n.GetAttribute("style")
	if styleStr != "" {
		pairs := strings.Split(styleStr, ";")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, ":", 2)
			if len(kv) == 2 {
				prop := strings.TrimSpace(kv[0])
				val := strings.TrimSpace(kv[1])
				camelProp := cssToCamel(prop)
				obj.Set(camelProp, val)
			}
		}
	}

	obj.Set("setProperty", func(prop, value string) {
		camelProp := cssToCamel(prop)
		obj.Set(camelProp, value)
		// Update the inline style attribute
		updateInlineStyle(n, prop, value)
	})
	obj.Set("getPropertyValue", func(prop string) string {
		val := n.GetAttribute("style")
		if val == "" {
			return ""
		}
		// Find the property
		prop = strings.TrimSpace(prop)
		pairs := strings.Split(val, ";")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, ":", 2)
			if len(kv) == 2 && strings.TrimSpace(kv[0]) == prop {
				return strings.TrimSpace(kv[1])
			}
		}
		return ""
	})
	obj.Set("removeProperty", func(prop string) {
		obj.Set(cssToCamel(prop), "")
		removeInlineStyle(n, prop)
	})
	obj.Set("cssText", styleStr)

	return obj
}

func cssToCamel(prop string) string {
	parts := strings.Split(prop, "-")
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

func updateInlineStyle(n *Node, prop, value string) {
	style := n.GetAttribute("style")
	// Remove existing property
	style = removeStyleProp(style, prop)
	if value != "" {
		if style != "" && !strings.HasSuffix(style, ";") {
			style += "; "
		}
		style += prop + ": " + value
	}
	n.SetAttribute("style", style)
}

func removeInlineStyle(n *Node, prop string) {
	style := n.GetAttribute("style")
	style = removeStyleProp(style, prop)
	n.SetAttribute("style", style)
}

func removeStyleProp(style, prop string) string {
	pairs := strings.Split(style, ";")
	var result []string
	for _, pair := range pairs {
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) == 2 && strings.TrimSpace(kv[0]) != prop {
			result = append(result, strings.TrimSpace(pair))
		}
	}
	return strings.Join(result, "; ")
}

func (env *BrowserEnv) wrapClassList(n *Node, obj *goja.Object) interface{} {
	vm := env.VM
	cl := vm.NewObject()
	cl.Set("add", func(classes ...string) {
		for _, cls := range classes {
			n.AddClass(cls)
		}
		obj.Set("className", strings.Join(n.ClassList(), " "))
	})
	cl.Set("remove", func(classes ...string) {
		for _, cls := range classes {
			n.RemoveClass(cls)
		}
		obj.Set("className", strings.Join(n.ClassList(), " "))
	})
	cl.Set("toggle", func(cls string) bool {
		if n.HasClass(cls) {
			n.RemoveClass(cls)
			obj.Set("className", strings.Join(n.ClassList(), " "))
			return false
		}
		n.AddClass(cls)
		obj.Set("className", strings.Join(n.ClassList(), " "))
		return true
	})
	cl.Set("contains", func(cls string) bool {
		return n.HasClass(cls)
	})
	cl.Set("length", len(n.ClassList()))
	cl.Set("value", strings.Join(n.ClassList(), " "))
	return cl
}

// wrapNodeListLazy returns an array-like object where nodes are wrapped on demand.
func (env *BrowserEnv) wrapNodeListLazy(nodes []*Node) interface{} {
	vm := env.VM
	arr := vm.NewObject()
	arr.Set("length", len(nodes))
	arr.Set("item", func(idx int) interface{} {
		if idx >= 0 && idx < len(nodes) {
			return env.WrapNode(nodes[idx])
		}
		return nil
	})
	arr.Set("forEach", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) > 0 {
			if fn, ok := goja.AssertFunction(call.Arguments[0]); ok {
				for i, node := range nodes {
					fn(goja.Undefined(), env.VM.ToValue(env.WrapNode(node)), env.VM.ToValue(i))
				}
			}
		}
		return goja.Undefined()
	})
	// Index access
	for i := range nodes {
		idx := i // capture
		arr.Set(strconv.Itoa(idx), func() interface{} {
			return env.WrapNode(nodes[idx])
		})
	}
	return arr
}

func (env *BrowserEnv) wrapFirstChild(n *Node) interface{} {
	if len(n.Children) > 0 {
		return env.WrapNode(n.Children[0])
	}
	return nil
}

func (env *BrowserEnv) wrapLastChild(n *Node) interface{} {
	if len(n.Children) > 0 {
		return env.WrapNode(n.Children[len(n.Children)-1])
	}
	return nil
}

func (env *BrowserEnv) wrapFirstElementChild(n *Node) interface{} {
	for _, child := range n.Children {
		if child.Type == ElementNode {
			return env.WrapNode(child)
		}
	}
	return nil
}

func (env *BrowserEnv) wrapLastElementChild(n *Node) interface{} {
	for i := len(n.Children) - 1; i >= 0; i-- {
		if n.Children[i].Type == ElementNode {
			return env.WrapNode(n.Children[i])
		}
	}
	return nil
}

func (env *BrowserEnv) wrapParent(n *Node) interface{} {
	if n.Parent == nil {
		return nil
	}
	return env.WrapNode(n.Parent)
}

func (env *BrowserEnv) wrapNextSibling(n *Node) interface{} {
	next := n.NextSibling()
	if next == nil {
		return nil
	}
	return env.WrapNode(next)
}

func (env *BrowserEnv) wrapPrevSibling(n *Node) interface{} {
	prev := n.PreviousSibling()
	if prev == nil {
		return nil
	}
	return env.WrapNode(prev)
}

func (env *BrowserEnv) wrapNextElementSibling(n *Node) interface{} {
	next := n.NextElementSibling()
	if next == nil {
		return nil
	}
	return env.WrapNode(next)
}

func (env *BrowserEnv) wrapPrevElementSibling(n *Node) interface{} {
	prev := n.PreviousElementSibling()
	if prev == nil {
		return nil
	}
	return env.WrapNode(prev)
}

func (env *BrowserEnv) unwrapNode(val goja.Value) *Node {
	if val == nil || goja.IsNull(val) || goja.IsUndefined(val) {
		return nil
	}
	obj := val.ToObject(env.VM)
	if obj == nil {
		return nil
	}
	raw := obj.Get("__domNode__")
	if raw == nil || goja.IsUndefined(raw) {
		return nil
	}
	if n, ok := raw.Export().(*Node); ok {
		return n
	}
	return nil
}

// strconv helper
func itoa(i int) string {
	return strconv.Itoa(i) // already imported via "strings"
}
