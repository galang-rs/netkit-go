package js

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bacot120211/netkit-go/pkg/js/dom"
	"github.com/dop251/goja"
)

// RegisterDOMModule injects the global `html()` function into the Goja VM.
// Provides server-side DOM manipulation with CSS selectors, cookies, and storage.
//
// JS API:
//
//	const doc = html('<html><body><h1>Hello</h1></body></html>', {
//	    url: 'https://example.com',
//	    proxy: 'socks5://...'
//	});
//	doc.querySelector('h1').text          // → "Hello"
//	doc.querySelectorAll('.item')         // → [...]
//	doc.setCookie('name', 'value')
//	doc.setStorage('key', 'value')
//	doc.serialize()                       // → modified HTML string
//	doc.close()
func RegisterDOMModule(r *Runtime, m map[string]interface{}) {
	vm := r.vm

	vm.Set("html", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			panic(vm.ToValue("html() requires an HTML string argument"))
		}

		htmlStr := call.Arguments[0].String()

		// Parse options
		docURL := ""
		proxyAddr := ""
		execScripts := false
		scriptTimeout := 30 // default 30s per script

		if len(call.Arguments) > 1 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
			opts := call.Arguments[1].Export()
			if optsMap, ok := opts.(map[string]interface{}); ok {
				if u, ok := optsMap["url"].(string); ok {
					docURL = u
				}
				if p, ok := optsMap["proxy"].(string); ok {
					proxyAddr = p
				}
				if es, ok := optsMap["executeScripts"].(bool); ok {
					execScripts = es
				}
				if st, ok := optsMap["scriptTimeout"]; ok {
					scriptTimeout = toInt(st, scriptTimeout)
				}
			}
		}

		// Parse HTML
		doc, err := dom.ParseWithURL(htmlStr, docURL)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("html() parse error: %v", err)))
		}

		_ = proxyAddr // stored for future fetch integration

		// Execute page scripts if requested
		if execScripts {
			r.Unlock() // release lock for network calls
			executePageScripts(doc, scriptTimeout)
			r.Lock()
		}

		return vm.ToValue(wrapDocument(r, vm, doc, proxyAddr))
	})
}

// wrapDocument creates a JS-accessible object for a Document.
func wrapDocument(r *Runtime, vm *goja.Runtime, doc *dom.Document, proxyAddr string) map[string]interface{} {
	// navigateDoc fetches a URL, re-parses HTML, and updates doc in-place.
	navigateDoc := func(targetURL string) (string, error) {
		r.Unlock()
		body, finalURL, err := domFetch(targetURL)
		r.Lock()
		if err != nil {
			return "", err
		}
		newDoc, err := dom.ParseWithURL(body, finalURL)
		if err != nil {
			return "", err
		}
		// Replace doc content in-place
		doc.Root.Children = newDoc.Root.Children
		// Re-parent children to old root
		for _, child := range doc.Root.Children {
			child.Parent = doc.Root
		}
		doc.URL = finalURL
		doc.DocType = newDoc.DocType
		if newDoc.Images != nil {
			doc.Images.Clear()
		}
		return finalURL, nil
	}

	return map[string]interface{}{
		// ──── Selectors ────
		"querySelector": func(sel string) interface{} {
			node := doc.QuerySelector(sel)
			if node == nil {
				return nil
			}
			return wrapNode(vm, node)
		},
		"querySelectorAll": func(sel string) interface{} {
			nodes := doc.QuerySelectorAll(sel)
			result := make([]interface{}, len(nodes))
			for i, n := range nodes {
				result[i] = wrapNode(vm, n)
			}
			return result
		},
		"select": func(sel string) interface{} {
			nodes := doc.QuerySelectorAll(sel)
			result := make([]interface{}, len(nodes))
			for i, n := range nodes {
				result[i] = wrapNode(vm, n)
			}
			return result
		},
		"getElementById": func(id string) interface{} {
			node := doc.GetElementByID(id)
			if node == nil {
				return nil
			}
			return wrapNode(vm, node)
		},
		"getElementsByTagName": func(tag string) interface{} {
			nodes := doc.Root.GetElementsByTagName(tag)
			result := make([]interface{}, len(nodes))
			for i, n := range nodes {
				result[i] = wrapNode(vm, n)
			}
			return result
		},
		"getElementsByClassName": func(cls string) interface{} {
			nodes := doc.Root.GetElementsByClassName(cls)
			result := make([]interface{}, len(nodes))
			for i, n := range nodes {
				result[i] = wrapNode(vm, n)
			}
			return result
		},

		// ──── Content Access ────
		"innerHTML": func() string {
			if body := doc.Body(); body != nil {
				return dom.SerializeChildren(body)
			}
			return dom.SerializeChildren(doc.Root)
		},
		"textContent": func() string {
			return doc.Root.TextContent()
		},
		"title": func() string {
			return doc.Title()
		},

		// ──── DOM Manipulation ────
		"setInnerHTML": func(selector, html string) bool {
			node := doc.QuerySelector(selector)
			if node == nil {
				return false
			}
			// Clear existing children
			node.Children = node.Children[:0]
			// Parse and append new children
			fragments, err := dom.ParseFragment(html)
			if err != nil {
				return false
			}
			for _, f := range fragments {
				node.AppendChild(f)
			}
			return true
		},
		"setAttribute": func(selector, attr, value string) bool {
			node := doc.QuerySelector(selector)
			if node == nil {
				return false
			}
			node.SetAttribute(attr, value)
			return true
		},
		"getAttribute": func(selector, attr string) interface{} {
			node := doc.QuerySelector(selector)
			if node == nil {
				return nil
			}
			if !node.HasAttribute(attr) {
				return nil
			}
			return node.GetAttribute(attr)
		},
		"removeElement": func(selector string) int {
			nodes := doc.QuerySelectorAll(selector)
			for _, n := range nodes {
				n.Remove()
			}
			return len(nodes)
		},
		"appendHTML": func(selector, html string) bool {
			node := doc.QuerySelector(selector)
			if node == nil {
				return false
			}
			fragments, err := dom.ParseFragment(html)
			if err != nil {
				return false
			}
			for _, f := range fragments {
				node.AppendChild(f)
			}
			return true
		},
		"prependHTML": func(selector, html string) bool {
			node := doc.QuerySelector(selector)
			if node == nil {
				return false
			}
			fragments, err := dom.ParseFragment(html)
			if err != nil {
				return false
			}
			// Prepend in reverse order to maintain order
			for i := len(fragments) - 1; i >= 0; i-- {
				node.PrependChild(fragments[i])
			}
			return true
		},
		"addClass": func(selector, cls string) bool {
			node := doc.QuerySelector(selector)
			if node == nil {
				return false
			}
			if !node.HasClass(cls) {
				existing := node.GetAttribute("class")
				if existing != "" {
					node.SetAttribute("class", existing+" "+cls)
				} else {
					node.SetAttribute("class", cls)
				}
			}
			return true
		},
		"removeClass": func(selector, cls string) bool {
			node := doc.QuerySelector(selector)
			if node == nil {
				return false
			}
			classes := node.ClassList()
			var newClasses []string
			for _, c := range classes {
				if c != cls {
					newClasses = append(newClasses, c)
				}
			}
			node.SetAttribute("class", strings.Join(newClasses, " "))
			return true
		},

		// ──── Cookie Management ────
		"setCookie": func(name, value string, opts ...map[string]interface{}) {
			var o map[string]interface{}
			if len(opts) > 0 {
				o = opts[0]
			}
			doc.Cookies.Set(name, value, o)
		},
		"getCookie": func(name string) interface{} {
			val := doc.Cookies.Get(name)
			if val == "" {
				return nil
			}
			return val
		},
		"getAllCookies": func() interface{} {
			cookies := doc.Cookies.GetAll()
			result := make([]interface{}, len(cookies))
			for i, c := range cookies {
				result[i] = map[string]interface{}{
					"name":     c.Name,
					"value":    c.Value,
					"domain":   c.Domain,
					"path":     c.Path,
					"secure":   c.Secure,
					"httpOnly": c.HTTPOnly,
				}
			}
			return result
		},
		"deleteCookie": func(name string) {
			doc.Cookies.Delete(name)
		},
		"clearCookies": func() {
			doc.Cookies.Clear()
		},
		"cookieString": func() string {
			return doc.Cookies.String()
		},

		// ──── Storage ────
		"setStorage": func(key, value string) {
			doc.Storage.SetItem(key, value)
		},
		"getStorage": func(key string) interface{} {
			val, ok := doc.Storage.GetItem(key)
			if !ok {
				return nil
			}
			return val
		},
		"removeStorage": func(key string) {
			doc.Storage.RemoveItem(key)
		},
		"clearStorage": func() {
			doc.Storage.Clear()
		},
		"storageLength": func() int {
			return doc.Storage.Length()
		},

		// ──── Serialization ────
		"serialize": func() string {
			return dom.Serialize(doc)
		},
		"snapshot": func() map[string]interface{} {
			// Build storage snapshot
			storageData := doc.Storage.Snapshot()

			// Build cookie snapshot
			cookies := doc.Cookies.GetAll()
			cookieList := make([]interface{}, len(cookies))
			for i, c := range cookies {
				cookieList[i] = map[string]interface{}{
					"name":  c.Name,
					"value": c.Value,
				}
			}

			return map[string]interface{}{
				"html":    dom.Serialize(doc),
				"url":     doc.URL,
				"cookies": cookieList,
				"storage": storageData,
			}
		},

		// ──── Screenshot & Viewport ────
		"screenshot": func(call goja.FunctionCall) goja.Value {
			opts := dom.DefaultRenderOptions()
			opts.Width = doc.ViewportW
			opts.Height = doc.ViewportH

			if len(call.Arguments) > 0 && !goja.IsUndefined(call.Arguments[0]) && !goja.IsNull(call.Arguments[0]) {
				raw := call.Arguments[0].Export()
				if m, ok := raw.(map[string]interface{}); ok {
					if w, ok := m["width"]; ok {
						opts.Width = toInt(w, opts.Width)
					}
					if h, ok := m["height"]; ok {
						opts.Height = toInt(h, opts.Height)
					}
					if sy, ok := m["scrollY"]; ok {
						opts.ScrollY = toInt(sy, 0)
					}
					if fp, ok := m["fullPage"]; ok {
						if b, ok := fp.(bool); ok {
							opts.FullPage = b
						}
					}
					if sel, ok := m["selector"]; ok {
						if s, ok := sel.(string); ok {
							opts.Selector = s
						}
					}
					if p, ok := m["path"]; ok {
						if s, ok := p.(string); ok {
							opts.Path = s
						}
					}
				}
			}

			path, err := dom.Screenshot(doc, opts)
			if err != nil {
				panic(vm.ToValue(fmt.Sprintf("screenshot error: %v", err)))
			}
			return vm.ToValue(path)
		},
		"pageInfo": func() map[string]interface{} {
			layout := dom.Layout(doc, doc.ViewportW, doc.ViewportH)
			scrollMax := layout.ContentHeight - doc.ViewportH
			if scrollMax < 0 {
				scrollMax = 0
			}
			return map[string]interface{}{
				"width":         doc.ViewportW,
				"height":        doc.ViewportH,
				"contentHeight": layout.ContentHeight,
				"scrollMin":     0,
				"scrollMax":     scrollMax,
			}
		},
		"setViewport": func(w, h int) {
			if w > 0 {
				doc.ViewportW = w
			}
			if h > 0 {
				doc.ViewportH = h
			}
		},

		// ──── Interaction ────
		"click": func(sel string) interface{} {
			node := doc.QuerySelector(sel)
			if node == nil {
				return nil
			}

			// Check if this is a form submit button/input
			isSubmit := false
			if strings.EqualFold(node.Tag, "input") || strings.EqualFold(node.Tag, "button") {
				inputType := strings.ToLower(node.GetAttribute("type"))
				if inputType == "submit" || (strings.EqualFold(node.Tag, "button") && inputType != "button" && inputType != "reset") {
					isSubmit = true
				}
			}

			if isSubmit {
				// Form submission: collect form data and POST
				form := findParentForm(node)
				if form == nil {
					fmt.Printf("[DOM] click: submit button has no parent <form>\n")
					return nil
				}

				action := form.GetAttribute("action")
				if action == "" {
					action = doc.URL // submit to same URL if no action
				}
				targetURL := dom.ResolveURL(action, doc.URL)
				method := strings.ToUpper(form.GetAttribute("method"))
				if method == "" {
					method = "GET"
				}

				// Collect form data
				formData := collectFormData(form)
				fmt.Printf("[DOM] form submit: %s %s (fields: %d)\n", method, targetURL, len(formData))

				r.Unlock()
				var body string
				var finalURL string
				var err error
				if method == "POST" {
					body, finalURL, err = domPostForm(targetURL, formData)
				} else {
					// GET: append form data as query string
					if len(formData) > 0 {
						sep := "?"
						if strings.Contains(targetURL, "?") {
							sep = "&"
						}
						targetURL += sep + formData.Encode()
					}
					body, finalURL, err = domFetch(targetURL)
				}
				r.Lock()

				if err != nil {
					fmt.Printf("[DOM] form submit error: %v\n", err)
					return targetURL
				}

				// Replace DOM with response
				newDoc, parseErr := dom.ParseWithURL(body, finalURL)
				if parseErr != nil {
					fmt.Printf("[DOM] form submit parse error: %v\n", parseErr)
					return finalURL
				}
				doc.Root.Children = newDoc.Root.Children
				for _, child := range doc.Root.Children {
					child.Parent = doc.Root
				}
				doc.URL = finalURL
				doc.DocType = newDoc.DocType
				return finalURL
			}

			// Non-form click: navigate via href
			href := findClickableURL(node)
			if href == "" {
				return nil
			}
			targetURL := dom.ResolveURL(href, doc.URL)
			finalURL, err := navigateDoc(targetURL)
			if err != nil {
				fmt.Printf("[DOM] click navigate error: %v\n", err)
				return targetURL
			}
			return finalURL
		},
		"clickText": func(text string) interface{} {
			anchors := doc.Root.GetElementsByTagName("a")
			lower := strings.ToLower(text)
			for _, a := range anchors {
				nodeText := strings.ToLower(strings.TrimSpace(a.TextContent()))
				if nodeText == lower || strings.Contains(nodeText, lower) {
					href := a.GetAttribute("href")
					if href != "" {
						targetURL := dom.ResolveURL(href, doc.URL)
						finalURL, err := navigateDoc(targetURL)
						if err != nil {
							fmt.Printf("[DOM] clickText navigate error: %v\n", err)
							return targetURL
						}
						return finalURL
					}
				}
			}
			return nil
		},
		"navigate": func(newURL string) interface{} {
			// Resolve relative URL
			resolved := dom.ResolveURL(newURL, doc.URL)
			// Update document URL
			doc.URL = resolved
			return resolved
		},
		"type": func(sel, value string) {
			node := doc.QuerySelector(sel)
			if node != nil {
				node.SetAttribute("value", value)
			}
		},
		"check": func(sel string) {
			node := doc.QuerySelector(sel)
			if node != nil {
				if node.GetAttribute("checked") != "" {
					node.RemoveAttribute("checked")
				} else {
					node.SetAttribute("checked", "checked")
				}
			}
		},
		"selectOption": func(sel, value string) {
			node := doc.QuerySelector(sel)
			if node != nil && strings.EqualFold(node.Tag, "select") {
				// Deselect all options, select the matching one
				for _, child := range node.Children {
					if strings.EqualFold(child.Tag, "option") {
						child.RemoveAttribute("selected")
						if child.GetAttribute("value") == value {
							child.SetAttribute("selected", "selected")
						}
					}
				}
			}
		},
		"links": func() interface{} {
			// Return all <a href> links as array of {text, href}
			anchors := doc.Root.GetElementsByTagName("a")
			var links []map[string]interface{}
			for _, a := range anchors {
				href := a.GetAttribute("href")
				if href == "" {
					continue
				}
				links = append(links, map[string]interface{}{
					"text": a.TextContent(),
					"href": dom.ResolveURL(href, doc.URL),
				})
			}
			return links
		},

		// ──── Fetch & Init ────
		"fetch": func(url string) interface{} {
			// Fetch directly (without navigateDoc's lock dance)
			// because fetch() may be called from contexts where the runtime
			// lock is not held (e.g. html("",{}).fetch("url") in tests).
			body, finalURL, err := domFetch(url)
			if err != nil {
				panic(vm.ToValue(fmt.Sprintf("fetch error: %v", err)))
			}
			newDoc, err := dom.ParseWithURL(body, finalURL)
			if err != nil {
				panic(vm.ToValue(fmt.Sprintf("fetch parse error: %v", err)))
			}
			// Replace doc content in-place
			doc.Root.Children = newDoc.Root.Children
			for _, child := range doc.Root.Children {
				child.Parent = doc.Root
			}
			doc.URL = finalURL
			doc.DocType = newDoc.DocType
			if newDoc.Images != nil {
				doc.Images.Clear()
			}
			return wrapDocument(r, vm, doc, proxyAddr)
		},

		// ──── Lifecycle ────
		"close": func() {
			// Cleanup temp files
			if doc.TempFiles != nil {
				doc.TempFiles.Cleanup()
			}
			// Clear DOM references
			doc.Root.Children = nil
			doc.Cookies.Clear()
			doc.Storage.Clear()
		},

		// ──── Document properties ────
		"url":     doc.URL,
		"doctype": doc.DocType,
	}
}

// wrapNode creates a JS-accessible object for a DOM Node.
func wrapNode(vm *goja.Runtime, n *dom.Node) map[string]interface{} {
	if n == nil {
		return nil
	}

	result := map[string]interface{}{
		"tag":         n.Tag,
		"text":        n.TextContent(),
		"html":        dom.SerializeNode(n),
		"innerHTML":   dom.SerializeChildren(n),
		"attrs":       n.Attrs,
		"id":          n.ID(),
		"classList":   n.ClassList(),
		"childCount":  len(n.Children),
	}

	// Selector methods on the node itself
	result["querySelector"] = func(sel string) interface{} {
		found := n.QuerySelector(sel)
		if found == nil {
			return nil
		}
		return wrapNode(vm, found)
	}
	result["querySelectorAll"] = func(sel string) interface{} {
		nodes := n.QuerySelectorAll(sel)
		list := make([]interface{}, len(nodes))
		for i, child := range nodes {
			list[i] = wrapNode(vm, child)
		}
		return list
	}

	// Attribute access
	result["getAttribute"] = func(key string) interface{} {
		if !n.HasAttribute(key) {
			return nil
		}
		return n.GetAttribute(key)
	}
	result["setAttribute"] = func(key, value string) {
		n.SetAttribute(key, value)
	}
	result["hasAttribute"] = func(key string) bool {
		return n.HasAttribute(key)
	}
	result["removeAttribute"] = func(key string) {
		n.RemoveAttribute(key)
	}

	// DOM manipulation
	result["setInnerHTML"] = func(html string) {
		n.Children = n.Children[:0]
		fragments, err := dom.ParseFragment(html)
		if err != nil {
			return
		}
		for _, f := range fragments {
			n.AppendChild(f)
		}
	}
	result["remove"] = func() {
		n.Remove()
	}
	result["children"] = func() interface{} {
		elems := n.ChildElements()
		list := make([]interface{}, len(elems))
		for i, child := range elems {
			list[i] = wrapNode(vm, child)
		}
		return list
	}
	result["parent"] = func() interface{} {
		if n.Parent == nil || n.Parent.Type == dom.DocumentNode {
			return nil
		}
		return wrapNode(vm, n.Parent)
	}
	result["nextSibling"] = func() interface{} {
		next := n.NextElementSibling()
		if next == nil {
			return nil
		}
		return wrapNode(vm, next)
	}
	result["previousSibling"] = func() interface{} {
		prev := n.PreviousElementSibling()
		if prev == nil {
			return nil
		}
		return wrapNode(vm, prev)
	}

	return result
}

// toInt converts various numeric types to int.
func toInt(v interface{}, fallback int) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case float32:
		return int(n)
	}
	return fallback
}

// findParentForm walks up the DOM tree to find a parent <form> element.
func findParentForm(n *dom.Node) *dom.Node {
	for p := n.Parent; p != nil; p = p.Parent {
		if strings.EqualFold(p.Tag, "form") {
			return p
		}
	}
	return nil
}

// findClickableURL finds a navigable URL from the clicked element.
// Search order: (1) self href, (2) ancestor <a>, (3) descendant <a>, (4) parent <form> action.
func findClickableURL(n *dom.Node) string {
	// 1. The element itself has an href
	if href := n.GetAttribute("href"); href != "" {
		return href
	}

	// 2. Walk up to find ancestor <a> with href
	for p := n.Parent; p != nil; p = p.Parent {
		if strings.EqualFold(p.Tag, "a") {
			if href := p.GetAttribute("href"); href != "" {
				return href
			}
		}
	}

	// 3. Look inside for descendant <a> with href
	links := n.GetElementsByTagName("a")
	for _, link := range links {
		if href := link.GetAttribute("href"); href != "" {
			return href
		}
	}

	// 4. Button/input → find parent <form> action
	if strings.EqualFold(n.Tag, "button") || strings.EqualFold(n.Tag, "input") {
		form := findParentForm(n)
		if form != nil {
			if action := form.GetAttribute("action"); action != "" {
				return action
			}
		}
	}

	return ""
}

// domFetch performs a simple HTTP GET for DOM navigation (click/navigate).
// Returns body string, final URL (after redirects), and error.
func domFetch(rawURL string) (string, string, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", rawURL, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return "", rawURL, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", rawURL, err
	}

	finalURL := resp.Request.URL.String()
	return string(body), finalURL, nil
}

// collectFormData collects all form input values as url.Values.
func collectFormData(form *dom.Node) url.Values {
	data := url.Values{}

	// Collect all input elements
	inputs := form.GetElementsByTagName("input")
	for _, input := range inputs {
		name := input.GetAttribute("name")
		if name == "" {
			continue
		}
		inputType := strings.ToLower(input.GetAttribute("type"))
		switch inputType {
		case "checkbox", "radio":
			if input.GetAttribute("checked") != "" {
				val := input.GetAttribute("value")
				if val == "" {
					val = "on"
				}
				data.Set(name, val)
			}
		case "submit", "button", "image", "reset", "file":
			// Skip these
		default:
			// text, password, hidden, email, number, etc.
			data.Set(name, input.GetAttribute("value"))
		}
	}

	// Collect select elements
	selects := form.GetElementsByTagName("select")
	for _, sel := range selects {
		name := sel.GetAttribute("name")
		if name == "" {
			continue
		}
		// Find selected option
		for _, opt := range sel.Children {
			if strings.EqualFold(opt.Tag, "option") && opt.GetAttribute("selected") != "" {
				data.Set(name, opt.GetAttribute("value"))
				break
			}
		}
	}

	// Collect textarea elements
	textareas := form.GetElementsByTagName("textarea")
	for _, ta := range textareas {
		name := ta.GetAttribute("name")
		if name == "" {
			continue
		}
		data.Set(name, ta.TextContent())
	}

	return data
}

// domPostForm POSTs form-encoded data and returns the response body, final URL, and error.
func domPostForm(rawURL string, data url.Values) (string, string, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequest("POST", rawURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", rawURL, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Referer", rawURL)

	resp, err := client.Do(req)
	if err != nil {
		return "", rawURL, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", rawURL, err
	}

	finalURL := resp.Request.URL.String()
	return string(body), finalURL, nil
}

// scriptTimeoutForSize calculates a scaled timeout based on script size.
// Base timeout is baseSeconds. For scripts > 100KB, add extra time proportionally.
func scriptTimeoutForSize(baseSeconds int, codeLen int) time.Duration {
	base := time.Duration(baseSeconds) * time.Second
	if codeLen <= 100*1024 {
		return base
	}
	// Add 30s per 500KB beyond 100KB
	extraKB := float64(codeLen-100*1024) / (500 * 1024)
	extra := time.Duration(math.Ceil(extraKB*30)) * time.Second
	return base + extra
}

// executePageScripts creates an isolated Goja VM, injects browser globals,
// and executes all <script> tags from the document (inline + external).
// baseTimeout is the per-script timeout in seconds (default 30).
func executePageScripts(doc *dom.Document, baseTimeout int) {
	// Collect all <script> tags in DOM order
	scripts := doc.Root.GetElementsByTagName("script")
	if len(scripts) == 0 {
		return
	}

	if baseTimeout <= 0 {
		baseTimeout = 30
	}

	// Create isolated VM for page scripts
	pageVM := goja.New()
	pageVM.SetFieldNameMapper(goja.UncapFieldNameMapper())

	// Inject browser-compatible globals (includes console, timers, fetch, etc.)
	env := dom.NewBrowserEnv(doc, pageVM)
	env.FetchFunc = domFetch
	env.InjectGlobals()

	// Track whether the VM was interrupted by timeout
	var timedOut sync.Mutex
	var timerRef *time.Timer

	stopTimer := func() {
		timedOut.Lock()
		defer timedOut.Unlock()
		if timerRef != nil {
			timerRef.Stop()
			timerRef = nil
		}
	}
	defer stopTimer()

	// resetTimer sets (or resets) the per-script timeout based on code size.
	resetTimer := func(codeLen int, label string) {
		stopTimer()
		dur := scriptTimeoutForSize(baseTimeout, codeLen)
		timedOut.Lock()
		timerRef = time.AfterFunc(dur, func() {
			fmt.Printf("[DOM Script] Timeout (%v) for: %s (%d bytes)\n", dur, label, codeLen)
			pageVM.Interrupt(fmt.Sprintf("script execution timeout (%v) — %s (%d bytes)", dur, label, codeLen))
		})
		timedOut.Unlock()
	}

	// Execute each script
	for i, script := range scripts {
		scriptType := strings.ToLower(script.GetAttribute("type"))
		// Skip non-JS scripts (e.g. type="application/json", type="text/template")
		if scriptType != "" && scriptType != "text/javascript" && scriptType != "application/javascript" && scriptType != "module" {
			continue
		}

		src := script.GetAttribute("src")
		var code string
		label := fmt.Sprintf("script#%d", i+1)

		if src != "" {
			// External script — download it
			resolvedSrc := dom.ResolveURL(src, doc.URL)
			body, _, err := domFetch(resolvedSrc)
			if err != nil {
				fmt.Printf("[DOM Script] Failed to download %s: %v\n", resolvedSrc, err)
				continue
			}
			code = body
			label = resolvedSrc
			fmt.Printf("[DOM Script] Loaded external: %s (%d bytes)\n", resolvedSrc, len(code))
		} else {
			// Inline script
			code = script.TextContent()
		}

		if strings.TrimSpace(code) == "" {
			continue
		}

		// Strip source map references — Goja tries to load them from disk
		code = stripSourceMapURL(code)

		// Reset per-script timeout (scaled by size)
		resetTimer(len(code), label)

		// Clear any previous interrupt before executing next script
		pageVM.ClearInterrupt()

		// Execute with panic recovery
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("[DOM Script] Runtime error: %v\n", r)
				}
			}()
			_, err := pageVM.RunString(code)
			if err != nil {
				// Log but don't stop — many scripts have non-critical errors
				fmt.Printf("[DOM Script] Error: %v\n", err)
			}
		}()
	}

	// Stop timer before draining timers
	stopTimer()
	pageVM.ClearInterrupt()

	// Limit pending timers to avoid draining thousands of stale callbacks
	// from massive bundles that timed out (e.g. React's recursive scheduler).
	if len(env.PendingTimers) > 100 {
		fmt.Printf("[DOM Script] Trimming pending timers from %d to 100\n", len(env.PendingTimers))
		env.PendingTimers = env.PendingTimers[:100]
	}

	// Drain pending timers (React needs many rounds for full rendering via MessageChannel/setTimeout)
	env.DrainTimers(20)

	// Freeze timer registrations — React scheduler settled, no more callbacks needed.
	// This prevents infinite spawning of new timers when user interacts with the DOM later.
	env.TimersFrozen = true

	fmt.Printf("[DOM Script] Execution complete. DOM now has %d elements\n", countElements(doc.Root))
}

func countElements(n *dom.Node) int {
	count := 0
	if n.Type == dom.ElementNode {
		count = 1
	}
	for _, child := range n.Children {
		count += countElements(child)
	}
	return count
}

// stripSourceMapURL removes //# sourceMappingURL=... and //# sourceURL=... from code.
// Goja tries to load .map files from disk, causing SyntaxError.
func stripSourceMapURL(code string) string {
	// Handle both // and /*  */ style comments
	for _, prefix := range []string{"//# sourceMappingURL=", "//@ sourceMappingURL=", "//# sourceURL="} {
		if idx := strings.LastIndex(code, prefix); idx >= 0 {
			end := strings.IndexByte(code[idx:], '\n')
			if end == -1 {
				code = code[:idx]
			} else {
				code = code[:idx] + code[idx+end:]
			}
		}
	}
	return code
}
