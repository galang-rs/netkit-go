package dom

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// NavigatorFingerprint holds browser fingerprint data for the navigator object.
// Populate from http-interperation's browser.Profile or browser.BrowserFingerprint.
// When nil on BrowserEnv, hardcoded defaults are used (backward compatible).
type NavigatorFingerprint struct {
	UserAgent           string
	Platform            string
	Language            string
	Languages           []string
	Vendor              string
	VendorSub           string
	ProductSub          string
	AppCodeName         string
	AppName             string
	AppVersion          string
	HardwareConcurrency int
	MaxTouchPoints      int
	DeviceMemory        int
	ScreenWidth         int
	ScreenHeight        int
	ColorDepth          int
	PixelRatio          float64
	DoNotTrack          string
	CookieEnabled       bool
	OnLine              bool
}

// BrowserEnv holds the browser-compatible environment for script execution.
type BrowserEnv struct {
	Doc           *Document
	VM            *goja.Runtime
	PendingTimers []func()
	TimerID       int
	TimersFrozen  bool                                                       // when true, new timer registrations are silently dropped
	FetchFunc     func(url string) (body string, finalURL string, err error)                                               // injectable fetch (GET-only, legacy)
	FullFetchFunc func(method, url string, headers map[string]string, body string) (int, map[string]string, string, error) // injectable fetch (full HTTP)
	NodeCache     map[*Node]*goja.Object                                                                                  // cache: same *Node → same goja.Object (React expando properties persist)
	Fingerprint   *NavigatorFingerprint                                      // optional; when set, navigator values come from this
}

// NewBrowserEnv creates a browser environment for script execution.
func NewBrowserEnv(doc *Document, vm *goja.Runtime) *BrowserEnv {
	return &BrowserEnv{
		Doc:           doc,
		VM:            vm,
		PendingTimers: make([]func(), 0),
		NodeCache:     make(map[*Node]*goja.Object),
	}
}

// SetFingerprint sets the browser fingerprint for navigator/screen values.
func (env *BrowserEnv) SetFingerprint(fp *NavigatorFingerprint) {
	env.Fingerprint = fp
}

// DrainTimers executes pending timer callbacks for up to maxRounds.
// Also caps total callbacks to prevent infinite scheduler loops (e.g. React).
// A total deadline of 10 seconds prevents hanging if callbacks keep spawning.
// DOM stability detection: stops early if the DOM element count hasn't changed
// for 3 consecutive rounds (React scheduler settled).
func (env *BrowserEnv) DrainTimers(maxRounds int) {
	totalCallbacks := 0
	maxCallbacks := 2000 // safety cap (React reconciliation needs many rounds)
	deadline := time.Now().Add(10 * time.Second)

	// DOM stability tracking
	lastElementCount := countDOMElements(env.Doc.Root)
	stableRounds := 0
	maxStableRounds := 30 // React's fiber reconciliation may take many rounds before committing

	// Set per-round timeout to interrupt the VM if a single callback hangs
	var roundTimer *time.Timer
	defer func() {
		if roundTimer != nil {
			roundTimer.Stop()
		}
	}()

	for round := 0; round < maxRounds && len(env.PendingTimers) > 0 && totalCallbacks < maxCallbacks; round++ {
		if time.Now().After(deadline) {
			fmt.Println("[DOM Script] DrainTimers: total deadline exceeded, stopping")
			break
		}

		batch := env.PendingTimers
		env.PendingTimers = make([]func(), 0)
		for _, fn := range batch {
			if totalCallbacks >= maxCallbacks || time.Now().After(deadline) {
				break
			}
			totalCallbacks++

			// Per-callback timeout: interrupt VM after 2s per callback
			if roundTimer != nil {
				roundTimer.Stop()
			}
			env.VM.ClearInterrupt()
			roundTimer = time.AfterFunc(2*time.Second, func() {
				env.VM.Interrupt("DrainTimers: callback timeout (2s)")
			})

			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Printf("[DrainTimers] callback panic (recovered): %v\n", r)
					}
				}()
				fn()
			}()
		}

		// Check DOM stability after each round
		currentCount := countDOMElements(env.Doc.Root)
		if currentCount == lastElementCount {
			stableRounds++
			if stableRounds >= maxStableRounds {
				fmt.Printf("[DOM Script] DrainTimers: DOM stable (%d elements, %d rounds unchanged), stopping early\n", currentCount, stableRounds)
				break
			}
		} else {
			stableRounds = 0
			lastElementCount = currentCount
		}
	}

	// Final cleanup
	if roundTimer != nil {
		roundTimer.Stop()
	}
	env.VM.ClearInterrupt()
}

// countDOMElements counts all element nodes in the DOM tree.
func countDOMElements(n *Node) int {
	if n == nil {
		return 0
	}
	count := 0
	if n.Type == ElementNode {
		count = 1
	}
	for _, child := range n.Children {
		count += countDOMElements(child)
	}
	return count
}

// InjectGlobals sets up window, document, and other browser globals in the VM.
func (env *BrowserEnv) InjectGlobals() {
	vm := env.VM
	doc := env.Doc

	// ── shared location object ──
	locationObj := env.createLocationObject()

	// ── document object ──
	// IMPORTANT: Must construct as goja.Object (not map) so DefineAccessorProperty works
	documentMap := env.createDocumentObject()
	documentMap["location"] = locationObj
	documentMap["URL"] = doc.URL
	delete(documentMap, "body")
	delete(documentMap, "head")

	docObj := vm.NewObject()
	for k, v := range documentMap {
		docObj.Set(k, v)
	}
	vm.Set("document", docObj)

	// Define body/head/documentElement as property getters (React accesses these as properties)
	docObj.DefineAccessorProperty("body", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		bodyNode := doc.Body()
		if bodyNode == nil {
			return goja.Null()
		}
		return vm.ToValue(env.WrapNode(bodyNode))
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	docObj.DefineAccessorProperty("head", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		headNode := doc.Head()
		if headNode == nil {
			return goja.Null()
		}
		return vm.ToValue(env.WrapNode(headNode))
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	docObj.DefineAccessorProperty("documentElement", vm.ToValue(func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(env.WrapNode(doc.Root))
	}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)

	// ── localStorage / sessionStorage (must be on VM global for bare access) ──
	storageMap := doc.Storage.AsMap()
	vm.Set("localStorage", storageMap)
	vm.Set("sessionStorage", storageMap)

	// ── window object ──
	windowObj := env.createWindowObject(documentMap)
	vm.Set("window", windowObj)

	// window === globalThis
	vm.Set("globalThis", windowObj)
	vm.Set("self", windowObj)

	// ── Sync JS built-in globals to window object ──
	// Webpack's global polyfill (module 14823) checks e.Math === Math to validate
	// the global object. Without Math on window, it falls back to an internal scope
	// that lacks navigator, causing TypeError: Cannot read property 'userAgent' of undefined.
	builtins := []string{
		"Math", "JSON", "Object", "Array", "String", "Number", "Boolean", "Date",
		"RegExp", "Error", "TypeError", "RangeError", "SyntaxError", "ReferenceError",
		"Map", "Set", "WeakMap", "WeakSet", "Promise", "Symbol", "Proxy", "Reflect",
		"parseInt", "parseFloat", "isNaN", "isFinite", "NaN", "Infinity",
		"encodeURIComponent", "decodeURIComponent", "encodeURI", "decodeURI",
		"ArrayBuffer", "DataView", "Int8Array", "Uint8Array", "Float32Array", "Float64Array",
		"setTimeout", "clearTimeout", "setInterval", "clearInterval",
		"requestAnimationFrame", "cancelAnimationFrame", "queueMicrotask",
		"console", "navigator", "location", "document",
		"localStorage", "sessionStorage", "crypto", "performance",
		"fetch", "getComputedStyle", "getSelection", "matchMedia",
		"atob", "btoa",
	}
	for _, name := range builtins {
		if v := vm.Get(name); v != nil && !goja.IsUndefined(v) {
			windowObj.Set(name, v)
		}
	}

	// ── navigator (fingerprint-aware) ──
	// When env.Fingerprint is set, navigator values come from the fingerprint.
	// Otherwise, hardcoded defaults are used for backward compatibility.
	fp := env.Fingerprint
	navUserAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	navLanguage := "en-US"
	navLanguages := []string{"en-US", "en"}
	navPlatform := "Win32"
	navCookieEnabled := true
	navOnLine := true
	navHardwareConcurrency := 8
	navMaxTouchPoints := 0
	navVendor := "Google Inc."
	navVendorSub := ""
	navProductSub := "20030107"
	navAppName := "Netscape"
	navAppVersion := "5.0"
	navDeviceMemory := 8

	if fp != nil {
		if fp.UserAgent != "" {
			navUserAgent = fp.UserAgent
		}
		if fp.Language != "" {
			navLanguage = fp.Language
		}
		if len(fp.Languages) > 0 {
			navLanguages = fp.Languages
		}
		if fp.Platform != "" {
			navPlatform = fp.Platform
		}
		navCookieEnabled = fp.CookieEnabled
		navOnLine = fp.OnLine
		if fp.HardwareConcurrency > 0 {
			navHardwareConcurrency = fp.HardwareConcurrency
		}
		navMaxTouchPoints = fp.MaxTouchPoints
		if fp.Vendor != "" {
			navVendor = fp.Vendor
		}
		if fp.VendorSub != "" {
			navVendorSub = fp.VendorSub
		}
		if fp.ProductSub != "" {
			navProductSub = fp.ProductSub
		}
		if fp.AppName != "" {
			navAppName = fp.AppName
		}
		if fp.AppVersion != "" {
			navAppVersion = fp.AppVersion
		}
		if fp.DeviceMemory > 0 {
			navDeviceMemory = fp.DeviceMemory
		}
	}

	vm.Set("navigator", map[string]interface{}{
		"userAgent":            navUserAgent,
		"language":             navLanguage,
		"languages":            navLanguages,
		"platform":             navPlatform,
		"cookieEnabled":        navCookieEnabled,
		"onLine":               navOnLine,
		"hardwareConcurrency":  navHardwareConcurrency,
		"maxTouchPoints":       navMaxTouchPoints,
		"vendor":               navVendor,
		"vendorSub":            navVendorSub,
		"product":              "Gecko",
		"productSub":           navProductSub,
		"appName":              navAppName,
		"appVersion":           navAppVersion,
		"deviceMemory":         navDeviceMemory,
		"serviceWorker": map[string]interface{}{
			"register": func(url string, opts ...interface{}) interface{} {
				promise, _, reject := vm.NewPromise()
				reject(vm.ToValue("Service workers are not supported"))
				return vm.ToValue(promise)
			},
			"ready": func() interface{} {
				promise, _, _ := vm.NewPromise()
				return vm.ToValue(promise) // never resolves
			},
			"controller": nil,
			"getRegistrations": func() interface{} {
				promise, resolve, _ := vm.NewPromise()
				resolve(vm.NewArray())
				return vm.ToValue(promise)
			},
			"addEventListener":    func(t string, fn interface{}) {},
			"removeEventListener": func(t string, fn interface{}) {},
		},
		"mediaDevices": map[string]interface{}{
			"getUserMedia": func(constraints interface{}) interface{} {
				promise, _, reject := vm.NewPromise()
				reject(vm.ToValue("Not supported"))
				return vm.ToValue(promise)
			},
			"enumerateDevices": func() interface{} {
				promise, resolve, _ := vm.NewPromise()
				resolve(vm.NewArray())
				return vm.ToValue(promise)
			},
		},
		"credentials": map[string]interface{}{
			"get": func(opts interface{}) interface{} {
				p, _, rej := vm.NewPromise()
				rej(vm.ToValue("NotSupportedError: credentials.get is not supported"))
				return vm.ToValue(p)
			},
			"create": func(opts interface{}) interface{} {
				p, _, rej := vm.NewPromise()
				rej(vm.ToValue("NotSupportedError: credentials.create is not supported"))
				return vm.ToValue(p)
			},
			"store": func(cred interface{}) interface{} {
				p, _, rej := vm.NewPromise()
				rej(vm.ToValue("NotSupportedError: credentials.store is not supported"))
				return vm.ToValue(p)
			},
			"preventSilentAccess": func() interface{} {
				p, res, _ := vm.NewPromise()
				res(goja.Undefined())
				return vm.ToValue(p)
			},
		},
		"clipboard": map[string]interface{}{
			"readText":  func() interface{} { p, r, _ := vm.NewPromise(); r(vm.ToValue("")); return vm.ToValue(p) },
			"writeText": func(text string) interface{} { p, r, _ := vm.NewPromise(); r(vm.ToValue(nil)); return vm.ToValue(p) },
		},
		"permissions": map[string]interface{}{
			"query": func(opts interface{}) interface{} {
				promise, resolve, _ := vm.NewPromise()
				resolve(vm.ToValue(map[string]interface{}{
					"state":    "denied",
					"onchange": nil,
				}))
				return vm.ToValue(promise)
			},
		},
		"storage": map[string]interface{}{
			"estimate": func() interface{} {
				promise, resolve, _ := vm.NewPromise()
				resolve(vm.ToValue(map[string]interface{}{"quota": 0, "usage": 0}))
				return vm.ToValue(promise)
			},
		},
		"locks": map[string]interface{}{
			"request": func(name string, opts ...interface{}) interface{} {
				p, _, rej := vm.NewPromise()
				rej(vm.ToValue("NotSupportedError: Web Locks API is not supported"))
				return vm.ToValue(p)
			},
			"query": func() interface{} {
				p, res, _ := vm.NewPromise()
				res(vm.ToValue(map[string]interface{}{
					"held":    []interface{}{},
					"pending": []interface{}{},
				}))
				return vm.ToValue(p)
			},
		},
		"sendBeacon": func(url string, data ...interface{}) bool { return false },
		"vibrate":    func(pattern interface{}) bool { return false },
	})
	// Sync navigator to window AFTER it's defined (builtins sync above ran before navigator existed)
	windowObj.Set("navigator", vm.Get("navigator"))

	// ── location (share the same instance) ──
	vm.Set("location", locationObj)

	// ── history (must be on VM global for bare access) ──
	vm.Set("history", map[string]interface{}{
		"pushState":    func(state, title interface{}, url string) {},
		"replaceState": func(state, title interface{}, url string) {},
		"back":         func() {},
		"forward":      func() {},
		"go":           func(delta int) {},
		"length":       1,
		"state":        nil,
	})

	// ── Event constructors (JS-defined for proper `new` support) ──
	vm.RunString(`
		function Event(type, init) {
			this.type = type || '';
			this.bubbles = (init && init.bubbles) || false;
			this.cancelable = (init && init.cancelable) || false;
			this.composed = (init && init.composed) || false;
			this.defaultPrevented = false;
			this.isTrusted = false;
			this.target = null;
			this.currentTarget = null;
			this.eventPhase = 0;
			this.timeStamp = Date.now();
			this.preventDefault = function() { this.defaultPrevented = true; };
			this.stopPropagation = function() {};
			this.stopImmediatePropagation = function() {};
		}
		function CustomEvent(type, init) {
			Event.call(this, type, init);
			this.detail = (init && init.detail !== undefined) ? init.detail : null;
		}
		CustomEvent.prototype = Object.create(Event.prototype);
		CustomEvent.prototype.constructor = CustomEvent;
	`)

	// ── Base64 ──
	vm.Set("atob", func(s string) string {
		data, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			// Try URL-safe decoding
			data, err = base64.RawStdEncoding.DecodeString(s)
			if err != nil {
				return ""
			}
		}
		return string(data)
	})
	vm.Set("btoa", func(s string) string {
		return base64.StdEncoding.EncodeToString([]byte(s))
	})

	// ── requestAnimationFrame ──
	vm.Set("requestAnimationFrame", func(call goja.FunctionCall) goja.Value {
		// Defer callback to PendingTimers (React scheduler calls rAF recursively)
		env.TimerID++
		if !env.TimersFrozen && len(call.Arguments) > 0 {
			if fn, ok := goja.AssertFunction(call.Arguments[0]); ok {
				fnCopy := fn
				env.PendingTimers = append(env.PendingTimers, func() {
					fnCopy(goja.Undefined(), vm.ToValue(0))
				})
			}
		}
		return vm.ToValue(env.TimerID)
	})
	vm.Set("cancelAnimationFrame", func(id int) {})

	// ── Observers, Encoder/Decoder, DOM constructors — all as JS constructors for `new` support ──
	vm.RunString(`
		// MutationObserver
		function MutationObserver(callback) {
			this._callback = callback;
		}
		MutationObserver.prototype.observe = function(target, opts) {};
		MutationObserver.prototype.disconnect = function() {};
		MutationObserver.prototype.takeRecords = function() { return []; };

		// ResizeObserver
		function ResizeObserver(callback) {
			this._callback = callback;
		}
		ResizeObserver.prototype.observe = function(target) {};
		ResizeObserver.prototype.unobserve = function(target) {};
		ResizeObserver.prototype.disconnect = function() {};

		// IntersectionObserver
		function IntersectionObserver(callback, opts) {
			this._callback = callback;
		}
		IntersectionObserver.prototype.observe = function(target) {};
		IntersectionObserver.prototype.unobserve = function(target) {};
		IntersectionObserver.prototype.disconnect = function() {};

		// PerformanceObserver
		function PerformanceObserver(callback) {
			this._callback = callback;
		}
		PerformanceObserver.prototype.observe = function(opts) {};
		PerformanceObserver.prototype.disconnect = function() {};
		PerformanceObserver.supportedEntryTypes = [];
	`)

	// ── Performance (stub) ──
	vm.Set("performance", map[string]interface{}{
		"now": func() float64 { return 0 },
		"mark": func(name string) {},
		"measure": func(name string, start, end string) {},
		"getEntriesByType": func(t string) interface{} { return []interface{}{} },
		"getEntriesByName": func(name string) interface{} { return []interface{}{} },
	})

	// ── matchMedia (stub) ──
	vm.Set("matchMedia", func(query string) interface{} {
		return map[string]interface{}{
			"matches":             false,
			"media":               query,
			"addEventListener":    func(t string, fn interface{}) {},
			"removeEventListener": func(t string, fn interface{}) {},
			"addListener":         func(fn interface{}) {},
			"removeListener":      func(fn interface{}) {},
		}
	})

	// ── URL / URLSearchParams (top-level scope for proper prototype chain) ──
	vm.RunString(`
		// URLSearchParams
		function URLSearchParams(init) {
			this._entries = [];
			if (typeof init === 'string') {
				var s = init.charAt(0) === '?' ? init.substring(1) : init;
				var pairs = s.split('&');
				for (var i = 0; i < pairs.length; i++) {
					var pair = pairs[i].split('=');
					if (pair[0]) this._entries.push([decodeURIComponent(pair[0]), decodeURIComponent(pair[1] || '')]);
				}
			} else if (init && typeof init === 'object') {
				var keys = Object.keys(init);
				for (var i = 0; i < keys.length; i++) {
					this._entries.push([keys[i], String(init[keys[i]])]);
				}
			}
		}
		URLSearchParams.prototype.append = function(name, value) { this._entries.push([String(name), String(value)]); };
		URLSearchParams.prototype.delete = function(name) { this._entries = this._entries.filter(function(e) { return e[0] !== name; }); };
		URLSearchParams.prototype.get = function(name) { for (var i = 0; i < this._entries.length; i++) { if (this._entries[i][0] === name) return this._entries[i][1]; } return null; };
		URLSearchParams.prototype.getAll = function(name) { return this._entries.filter(function(e) { return e[0] === name; }).map(function(e) { return e[1]; }); };
		URLSearchParams.prototype.has = function(name) { for (var i = 0; i < this._entries.length; i++) { if (this._entries[i][0] === name) return true; } return false; };
		URLSearchParams.prototype.set = function(name, value) { var found = false; for (var i = 0; i < this._entries.length; i++) { if (this._entries[i][0] === name) { if (!found) { this._entries[i][1] = String(value); found = true; } else { this._entries.splice(i, 1); i--; } } } if (!found) this._entries.push([String(name), String(value)]); };
		URLSearchParams.prototype.sort = function() { this._entries.sort(function(a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; }); };
		URLSearchParams.prototype.toString = function() { return this._entries.map(function(e) { return encodeURIComponent(e[0]) + '=' + encodeURIComponent(e[1]); }).join('&'); };
		URLSearchParams.prototype.forEach = function(callback, thisArg) { for (var i = 0; i < this._entries.length; i++) { callback.call(thisArg, this._entries[i][1], this._entries[i][0], this); } };
		URLSearchParams.prototype.entries = function() { var i = 0, entries = this._entries; return { next: function() { if (i >= entries.length) return { done: true }; return { done: false, value: entries[i++] }; } }; };
		URLSearchParams.prototype.keys = function() { var i = 0, entries = this._entries; return { next: function() { if (i >= entries.length) return { done: true }; return { done: false, value: entries[i++][0] }; } }; };
		URLSearchParams.prototype.values = function() { var i = 0, entries = this._entries; return { next: function() { if (i >= entries.length) return { done: true }; return { done: false, value: entries[i++][1] }; } }; };
		if (typeof Symbol !== 'undefined' && Symbol.iterator) {
			URLSearchParams.prototype[Symbol.iterator] = URLSearchParams.prototype.entries;
		}

		// URL
		function URL(url, base) {
			if (base && url.indexOf('://') === -1) {
				if (url.charAt(0) === '/') { var m = base.match(/^(https?:\/\/[^\/]+)/); url = m ? m[1] + url : url; }
				else { url = base.replace(/[^\/]*$/, '') + url; }
			}
			this.href = url;
			var m = url.match(/^(https?:)\/\/([^\/:]+)(:\d+)?(\/[^?#]*)?(\?[^#]*)?(#.*)?$/);
			if (m) {
				this.protocol = m[1]; this.hostname = m[2]; this.port = m[3] ? m[3].substring(1) : '';
				this.host = m[2] + (m[3] || ''); this.pathname = m[4] || '/';
				this.search = m[5] || ''; this.hash = m[6] || '';
				this.origin = m[1] + '//' + this.host;
			} else {
				this.protocol = ''; this.hostname = ''; this.port = ''; this.host = '';
				this.pathname = url; this.search = ''; this.hash = ''; this.origin = '';
			}
			this.searchParams = new URLSearchParams(this.search);
			this.username = ''; this.password = '';
		}
		URL.prototype.toString = function() { return this.href; };
		URL.prototype.toJSON = function() { return this.href; };
		URL.createObjectURL = function(blob) { return 'blob:null/' + Math.random().toString(36).substring(2); };
		URL.revokeObjectURL = function(url) {};
	`)

	// ── XMLHttpRequest, DOMParser, getComputedStyle — JS constructors ──
	vm.RunString(`
		function XMLHttpRequest() {
			this.readyState = 0;
			this.status = 0;
			this.statusText = '';
			this.responseText = '';
			this.response = '';
			this._headers = {};
		}
		XMLHttpRequest.prototype.open = function(method, url, async) { this.readyState = 1; };
		XMLHttpRequest.prototype.send = function(body) {};
		XMLHttpRequest.prototype.setRequestHeader = function(key, value) { this._headers[key] = value; };
		XMLHttpRequest.prototype.getResponseHeader = function(key) { return null; };
		XMLHttpRequest.prototype.getAllResponseHeaders = function() { return ''; };
		XMLHttpRequest.prototype.abort = function() {};
		XMLHttpRequest.prototype.addEventListener = function(t, fn) {};
		XMLHttpRequest.prototype.removeEventListener = function(t, fn) {};
		XMLHttpRequest.UNSENT = 0; XMLHttpRequest.OPENED = 1; XMLHttpRequest.HEADERS_RECEIVED = 2;
		XMLHttpRequest.LOADING = 3; XMLHttpRequest.DONE = 4;

		function DOMParser() {}
		DOMParser.prototype.parseFromString = function(str, mimeType) { return null; };
	`)

	// ── getComputedStyle (returns proxy-like object) ──
	vm.Set("getComputedStyle", func(call goja.FunctionCall) goja.Value {
		defaults := map[string]string{
			"display":    "block",
			"visibility": "visible",
			"opacity":    "1",
			"position":   "static",
			"overflow":   "visible",
		}
		obj := vm.NewObject()
		obj.Set("getPropertyValue", func(prop string) string {
			if v, ok := defaults[prop]; ok {
				return v
			}
			return ""
		})
		for k, v := range defaults {
			obj.Set(k, v)
		}
		return vm.ToValue(obj)
	})

	// ── DOMException / AbortController / AbortSignal (top-level scope for goja global resolution) ──
	vm.RunString(`
		// DOMException MUST be defined first (used by AbortController/AbortSignal)
		function DOMException(message, name) {
			this.message = message || '';
			this.name = name || 'Error';
			var codes = {
				'IndexSizeError':1,'DOMStringSizeError':2,'HierarchyRequestError':3,
				'WrongDocumentError':4,'InvalidCharacterError':5,'NoDataAllowedError':6,
				'NoModificationAllowedError':7,'NotFoundError':8,'NotSupportedError':9,
				'InUseAttributeError':10,'InvalidStateError':11,'SyntaxError':12,
				'InvalidModificationError':13,'NamespaceError':14,'InvalidAccessError':15,
				'TypeMismatchError':17,'SecurityError':18,'NetworkError':19,
				'AbortError':20,'URLMismatchError':21,'QuotaExceededError':22,
				'TimeoutError':23,'InvalidNodeTypeError':24,'DataCloneError':25
			};
			this.code = codes[this.name] || 0;
		}
		DOMException.prototype = Object.create(Error.prototype);
		DOMException.prototype.constructor = DOMException;
		DOMException.prototype.toString = function() { return this.name + ': ' + this.message; };

		function AbortSignal() {
			this.aborted = false;
			this.reason = undefined;
			this._listeners = {};
		}
		AbortSignal.prototype.addEventListener = function(type, fn) {
			if (!this._listeners[type]) this._listeners[type] = [];
			this._listeners[type].push(fn);
		};
		AbortSignal.prototype.removeEventListener = function(type, fn) {
			if (!this._listeners[type]) return;
			this._listeners[type] = this._listeners[type].filter(function(f) { return f !== fn; });
		};
		AbortSignal.prototype.dispatchEvent = function(event) { return true; };
		AbortSignal.prototype.throwIfAborted = function() {
			if (this.aborted) throw new DOMException('The operation was aborted', 'AbortError');
		};
		AbortSignal.abort = function(reason) {
			var s = new AbortSignal();
			s.aborted = true;
			s.reason = reason || new DOMException('The operation was aborted', 'AbortError');
			return s;
		};
		AbortSignal.timeout = function(ms) { return new AbortSignal(); };
		AbortSignal.any = function(signals) { return new AbortSignal(); };

		function AbortController() {
			this.signal = new AbortSignal();
		}
		AbortController.prototype.abort = function(reason) {
			this.signal.aborted = true;
			this.signal.reason = reason || new DOMException('The operation was aborted', 'AbortError');
			var listeners = this.signal._listeners['abort'] || [];
			for (var i = 0; i < listeners.length; i++) {
				try { listeners[i]({ type: 'abort', target: this.signal }); } catch(e) {}
			}
		};
	`)

	// ── TextEncoder / TextDecoder / Blob / FormData / File — JS constructors ──
	vm.RunString(`
		function TextEncoder(encoding) {
			this.encoding = 'utf-8';
		}
		TextEncoder.prototype.encode = function(s) {
			if (!s) return new Uint8Array(0);
			var arr = [];
			for (var i = 0; i < s.length; i++) {
				var c = s.charCodeAt(i);
				if (c < 0x80) arr.push(c);
				else if (c < 0x800) { arr.push(0xC0 | (c >> 6)); arr.push(0x80 | (c & 0x3F)); }
				else { arr.push(0xE0 | (c >> 12)); arr.push(0x80 | ((c >> 6) & 0x3F)); arr.push(0x80 | (c & 0x3F)); }
			}
			return new Uint8Array(arr);
		};
		TextEncoder.prototype.encodeInto = function(s, dest) { return { read: 0, written: 0 }; };

		function TextDecoder(encoding) {
			this.encoding = encoding || 'utf-8';
		}
		TextDecoder.prototype.decode = function(input) {
			if (!input) return '';
			if (typeof input === 'string') return input;
			try { return String.fromCharCode.apply(null, new Uint8Array(input)); } catch(e) { return ''; }
		};

		function Blob(parts, opts) {
			this._parts = parts || [];
			this.type = (opts && opts.type) || '';
			var total = 0;
			for (var i = 0; i < this._parts.length; i++) {
				var p = this._parts[i];
				total += typeof p === 'string' ? p.length : (p.byteLength || p.length || 0);
			}
			this.size = total;
		}
		Blob.prototype.text = function() { return Promise.resolve(this._parts.join('')); };
		Blob.prototype.arrayBuffer = function() { return Promise.resolve(new ArrayBuffer(0)); };
		Blob.prototype.slice = function(start, end, type) {
			var content = this._parts.join('');
			var s = start || 0;
			var e = (end !== undefined) ? end : content.length;
			return new Blob([content.slice(s, e)], { type: type || this.type });
		};
		Blob.prototype.stream = function() { return null; };

		function File(parts, name, opts) {
			Blob.call(this, parts, opts);
			this.name = name || '';
			this.lastModified = Date.now();
		}
		File.prototype = Object.create(Blob.prototype);

		function FormData() {
			this._data = {};
		}
		FormData.prototype.append = function(key, value) {
			if (!this._data[key]) this._data[key] = [];
			this._data[key].push(value);
		};
		FormData.prototype.get = function(key) { return this._data[key] ? this._data[key][0] : null; };
		FormData.prototype.getAll = function(key) { return this._data[key] ? this._data[key].slice() : []; };
		FormData.prototype.set = function(key, value) { this._data[key] = [value]; };
		FormData.prototype.has = function(key) { return key in this._data; };
		FormData.prototype.delete = function(key) { delete this._data[key]; };
		FormData.prototype.entries = function() { var keys = Object.keys(this._data), i = 0, d = this._data; return { next: function() { if (i >= keys.length) return {done:true}; var k=keys[i++]; return {done:false, value:[k, d[k][0]]}; } }; };
	`)

	// ── Headers / Request / Response (top-level scope for proper prototype chain) ──
	vm.RunString(`
		// Headers
		function Headers(init) {
			this._headers = {};
			if (init && typeof init === 'object') {
				var keys = Object.keys(init);
				for (var i = 0; i < keys.length; i++) {
					this._headers[keys[i].toLowerCase()] = String(init[keys[i]]);
				}
			}
		}
		Headers.prototype.append = function(name, value) { this._headers[name.toLowerCase()] = String(value); };
		Headers.prototype.delete = function(name) { delete this._headers[name.toLowerCase()]; };
		Headers.prototype.get = function(name) { var v = this._headers[name.toLowerCase()]; return v !== undefined ? v : null; };
		Headers.prototype.has = function(name) { return name.toLowerCase() in this._headers; };
		Headers.prototype.set = function(name, value) { this._headers[name.toLowerCase()] = String(value); };
		Headers.prototype.forEach = function(callback, thisArg) { var h = this._headers; Object.keys(h).forEach(function(k) { callback.call(thisArg, h[k], k, this); }); };
		Headers.prototype.entries = function() { var keys = Object.keys(this._headers), i = 0, h = this._headers; return { next: function() { if (i >= keys.length) return {done:true}; var k = keys[i++]; return {done:false, value:[k, h[k]]}; } }; };
		Headers.prototype.keys = function() { var keys = Object.keys(this._headers), i = 0; return { next: function() { return i >= keys.length ? {done:true} : {done:false, value:keys[i++]}; } }; };
		Headers.prototype.values = function() { var keys = Object.keys(this._headers), i = 0, h = this._headers; return { next: function() { return i >= keys.length ? {done:true} : {done:false, value:h[keys[i++]]}; } }; };
		if (typeof Symbol !== 'undefined' && Symbol.iterator) {
			Headers.prototype[Symbol.iterator] = Headers.prototype.entries;
		}

		// Request
		function Request(input, init) {
			this.url = typeof input === 'string' ? input : (input && input.url) || '';
			this.method = (init && init.method) || 'GET';
			this.headers = new Headers((init && init.headers) || {});
			this.body = (init && init.body) || null;
			this.mode = (init && init.mode) || 'cors';
			this.credentials = (init && init.credentials) || 'same-origin';
			this.cache = (init && init.cache) || 'default';
			this.redirect = (init && init.redirect) || 'follow';
			this.referrer = 'about:client';
			this.signal = (init && init.signal) || new AbortSignal();
		}
		Request.prototype.clone = function() { return new Request(this.url, { method: this.method, headers: this.headers, body: this.body }); };
		Request.prototype.text = function() { return Promise.resolve(this.body || ''); };
		Request.prototype.json = function() { return Promise.resolve(this.body ? JSON.parse(this.body) : null); };

		// Response
		function Response(body, init) {
			this.body = body || null;
			this.ok = !init || !init.status || (init.status >= 200 && init.status < 300);
			this.status = (init && init.status) || 200;
			this.statusText = (init && init.statusText) || 'OK';
			this.headers = new Headers((init && init.headers) || {});
			this.type = 'default';
			this.url = '';
			this.redirected = false;
		}
		Response.prototype.clone = function() { return new Response(this.body, { status: this.status, statusText: this.statusText, headers: this.headers }); };
		Response.prototype.text = function() { return Promise.resolve(typeof this.body === 'string' ? this.body : ''); };
		Response.prototype.json = function() { var b = this.body; return Promise.resolve(typeof b === 'string' ? JSON.parse(b) : b); };
		Response.prototype.arrayBuffer = function() { return Promise.resolve(new ArrayBuffer(0)); };
		Response.prototype.blob = function() { return Promise.resolve(new Blob()); };
		Response.error = function() { return new Response(null, { status: 0, statusText: '' }); };
		Response.redirect = function(url, status) { return new Response(null, { status: status || 302, headers: { Location: url } }); };
	`)

	// ── process (Node.js compat for webpack bundles) ──
	vm.Set("process", map[string]interface{}{
		"env": map[string]interface{}{
			"NODE_ENV": "production",
		},
		"nextTick": func(call goja.FunctionCall) goja.Value {
			// Defer to PendingTimers (not synchronous — avoids recursion)
			if !env.TimersFrozen && len(call.Arguments) > 0 {
				if fn, ok := goja.AssertFunction(call.Arguments[0]); ok {
					fnCopy := fn
					env.PendingTimers = append(env.PendingTimers, func() {
						fnCopy(goja.Undefined())
					})
				}
			}
			return goja.Undefined()
		},
	})

	// ── crypto ──
	vm.Set("crypto", map[string]interface{}{
		"getRandomValues": func(call goja.FunctionCall) goja.Value {
			if len(call.Arguments) > 0 {
				obj := call.Arguments[0].ToObject(vm)
				if obj != nil {
					length := obj.Get("length")
					if length != nil && !goja.IsUndefined(length) {
						n := int(length.ToInteger())
						for i := 0; i < n; i++ {
							rv, _ := rand.Int(rand.Reader, big.NewInt(256))
							obj.Set(fmt.Sprintf("%d", i), vm.ToValue(rv.Int64()))
						}
					}
				}
				return call.Arguments[0]
			}
			return goja.Undefined()
		},
		"randomUUID": func() string {
			b := make([]byte, 16)
			rand.Read(b)
			b[6] = (b[6] & 0x0f) | 0x40
			b[8] = (b[8] & 0x3f) | 0x80
			return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
		},
		"subtle": CreateSubtleCrypto(vm),
	})

	// ── structuredClone (stub) ──
	vm.Set("structuredClone", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) > 0 {
			return call.Arguments[0]
		}
		return goja.Undefined()
	})

	// ── console ──
	vm.Set("console", map[string]interface{}{
		"log":      func(args ...interface{}) { fmt.Println(args...) },
		"warn":     func(args ...interface{}) { fmt.Println(append([]interface{}{"[warn]"}, args...)...) },
		"error":    func(args ...interface{}) { fmt.Println(append([]interface{}{"[error]"}, args...)...) },
		"info":     func(args ...interface{}) { fmt.Println(args...) },
		"debug":    func(args ...interface{}) {},
		"trace":    func(args ...interface{}) {},
		"dir":      func(args ...interface{}) {},
		"table":    func(args ...interface{}) {},
		"time":     func(label string) {},
		"timeEnd":  func(label string) {},
		"timeLog":  func(label string, args ...interface{}) {},
		"count":    func(label ...string) {},
		"countReset": func(label ...string) {},
		"group":    func(args ...interface{}) {},
		"groupCollapsed": func(args ...interface{}) {},
		"groupEnd": func() {},
		"clear":    func() {},
		"assert":   func(cond bool, args ...interface{}) {},
	})

	// ── setTimeout / setInterval / clearTimeout / clearInterval ──
	vm.Set("setTimeout", func(call goja.FunctionCall) goja.Value {
		env.TimerID++
		if !env.TimersFrozen && len(call.Arguments) > 0 {
			if fn, ok := goja.AssertFunction(call.Arguments[0]); ok {
				fnCopy := fn
				env.PendingTimers = append(env.PendingTimers, func() {
					fnCopy(goja.Undefined())
				})
			}
		}
		return vm.ToValue(env.TimerID)
	})
	vm.Set("setInterval", func(call goja.FunctionCall) goja.Value {
		env.TimerID++
		return vm.ToValue(env.TimerID)
	})
	vm.Set("clearTimeout", func(id int) {})
	vm.Set("clearInterval", func(id int) {})

	// ── queueMicrotask ──
	vm.Set("queueMicrotask", func(call goja.FunctionCall) goja.Value {
		if !env.TimersFrozen && len(call.Arguments) > 0 {
			if fn, ok := goja.AssertFunction(call.Arguments[0]); ok {
				fnCopy := fn
				env.PendingTimers = append(env.PendingTimers, func() {
					fnCopy(goja.Undefined())
				})
			}
		}
		return goja.Undefined()
	})

	// ── fetch (synchronous — goja VM is not thread-safe, no goroutines allowed) ──
	// Browser-compatible: resolves relative URLs, supports method/headers/body,
	// returns proper Response object.
	vm.Set("fetch", func(call goja.FunctionCall) goja.Value {
		promise, resolve, reject := vm.NewPromise()

		// ── Parse arguments ──
		rawURL := ""
		method := "GET"
		reqHeaders := map[string]string{}
		reqBody := ""

		if len(call.Arguments) > 0 {
			// First arg can be a string URL or a Request object
			firstArg := call.Arguments[0]
			if obj := firstArg.ToObject(vm); obj != nil {
				if urlProp := obj.Get("url"); urlProp != nil && !goja.IsUndefined(urlProp) {
					// Request object
					rawURL = urlProp.String()
					if m := obj.Get("method"); m != nil && !goja.IsUndefined(m) {
						method = strings.ToUpper(m.String())
					}
				} else {
					rawURL = firstArg.String()
				}
			} else {
				rawURL = firstArg.String()
			}
		}

		// Parse init options (2nd argument)
		if len(call.Arguments) > 1 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
			opts := call.Arguments[1].ToObject(vm)
			if m := opts.Get("method"); m != nil && !goja.IsUndefined(m) {
				method = strings.ToUpper(m.String())
			}
			if h := opts.Get("headers"); h != nil && !goja.IsUndefined(h) && !goja.IsNull(h) {
				hObj := h.ToObject(vm)
				for _, key := range hObj.Keys() {
					reqHeaders[key] = hObj.Get(key).String()
				}
			}
			if b := opts.Get("body"); b != nil && !goja.IsUndefined(b) && !goja.IsNull(b) {
				reqBody = b.String()
			}
		}

		// ── Resolve relative URLs against document URL ──
		resolvedURL := ResolveURL(rawURL, doc.URL)
		if resolvedURL == "" {
			resolvedURL = rawURL
		}

		// ── Execute fetch ──
		var statusCode int
		var respHeaders map[string]string
		var respBody string
		var fetchErr error

		if env.FullFetchFunc != nil {
			statusCode, respHeaders, respBody, fetchErr = env.FullFetchFunc(method, resolvedURL, reqHeaders, reqBody)
		} else if env.FetchFunc != nil {
			// Legacy GET-only fallback
			var body string
			body, _, fetchErr = env.FetchFunc(resolvedURL)
			if fetchErr == nil {
				statusCode = 200
				respHeaders = map[string]string{"content-type": "text/html"}
				respBody = body
			}
		} else {
			reject(vm.ToValue("fetch not available"))
			return vm.ToValue(promise)
		}

		if fetchErr != nil {
			reject(vm.ToValue(fetchErr.Error()))
			return vm.ToValue(promise)
		}

		// ── Build Response object ──
		if respHeaders == nil {
			respHeaders = map[string]string{}
		}

		// Build a Headers instance via the JS constructor
		headersObj := vm.NewObject()
		headersMap := vm.NewObject()
		for k, v := range respHeaders {
			headersMap.Set(strings.ToLower(k), v)
		}
		headersObj.Set("_headers", headersMap)
		headersObj.Set("get", func(name string) interface{} {
			low := strings.ToLower(name)
			if v, ok := respHeaders[low]; ok {
				return v
			}
			// Try original case
			for k, v := range respHeaders {
				if strings.EqualFold(k, name) {
					return v
				}
			}
			return nil
		})
		headersObj.Set("has", func(name string) bool {
			for k := range respHeaders {
				if strings.EqualFold(k, name) {
					return true
				}
			}
			return false
		})
		headersObj.Set("forEach", func(callback goja.Callable) {
			for k, v := range respHeaders {
				callback(goja.Undefined(), vm.ToValue(v), vm.ToValue(strings.ToLower(k)), vm.ToValue(headersObj))
			}
		})

		// Status text mapping
		statusText := "OK"
		switch statusCode {
		case 200:
			statusText = "OK"
		case 201:
			statusText = "Created"
		case 204:
			statusText = "No Content"
		case 301:
			statusText = "Moved Permanently"
		case 302:
			statusText = "Found"
		case 304:
			statusText = "Not Modified"
		case 400:
			statusText = "Bad Request"
		case 401:
			statusText = "Unauthorized"
		case 403:
			statusText = "Forbidden"
		case 404:
			statusText = "Not Found"
		case 500:
			statusText = "Internal Server Error"
		case 502:
			statusText = "Bad Gateway"
		case 503:
			statusText = "Service Unavailable"
		}

		// Body consumed flag
		bodyUsed := false
		checkBody := func() error {
			if bodyUsed {
				return fmt.Errorf("body has already been consumed")
			}
			bodyUsed = true
			return nil
		}

		respObj := vm.NewObject()
		respObj.Set("ok", statusCode >= 200 && statusCode < 300)
		respObj.Set("status", statusCode)
		respObj.Set("statusText", statusText)
		respObj.Set("url", resolvedURL)
		respObj.Set("type", "basic")
		respObj.Set("redirected", false)
		respObj.Set("bodyUsed", false)
		respObj.Set("headers", headersObj)

		respObj.Set("text", func() interface{} {
			p2, r2, rej2 := vm.NewPromise()
			if err := checkBody(); err != nil {
				rej2(vm.ToValue(err.Error()))
			} else {
				respObj.Set("bodyUsed", true)
				r2(vm.ToValue(respBody))
			}
			return vm.ToValue(p2)
		})
		respObj.Set("json", func() interface{} {
			p2, r2, rej2 := vm.NewPromise()
			if err := checkBody(); err != nil {
				rej2(vm.ToValue(err.Error()))
			} else {
				respObj.Set("bodyUsed", true)
				// Parse JSON via JS for proper type conversion
				jsonVal, jsErr := vm.RunString("(" + respBody + ")")
				if jsErr != nil {
					// Try JSON.parse as fallback
					vm.Set("__fetchJsonTmp", respBody)
					jsonVal, jsErr = vm.RunString("JSON.parse(__fetchJsonTmp)")
					vm.Set("__fetchJsonTmp", goja.Undefined())
				}
				if jsErr != nil {
					rej2(vm.ToValue("SyntaxError: Unexpected token in JSON"))
				} else {
					r2(jsonVal)
				}
			}
			return vm.ToValue(p2)
		})
		respObj.Set("arrayBuffer", func() interface{} {
			p2, r2, rej2 := vm.NewPromise()
			if err := checkBody(); err != nil {
				rej2(vm.ToValue(err.Error()))
			} else {
				respObj.Set("bodyUsed", true)
				r2(vm.ToValue(vm.NewArrayBuffer([]byte(respBody))))
			}
			return vm.ToValue(p2)
		})
		respObj.Set("blob", func() interface{} {
			p2, r2, rej2 := vm.NewPromise()
			if err := checkBody(); err != nil {
				rej2(vm.ToValue(err.Error()))
			} else {
				respObj.Set("bodyUsed", true)
				// Return a Blob-like object
				r2(vm.ToValue(map[string]interface{}{
					"size": len(respBody),
					"type": respHeaders["content-type"],
					"text": func() interface{} {
						p3, r3, _ := vm.NewPromise()
						r3(vm.ToValue(respBody))
						return vm.ToValue(p3)
					},
				}))
			}
			return vm.ToValue(p2)
		})
		respObj.Set("clone", func() interface{} {
			// clone() returns a new Response with reset bodyUsed
			cloneObj := vm.NewObject()
			cloneObj.Set("ok", statusCode >= 200 && statusCode < 300)
			cloneObj.Set("status", statusCode)
			cloneObj.Set("statusText", statusText)
			cloneObj.Set("url", resolvedURL)
			cloneObj.Set("type", "basic")
			cloneObj.Set("redirected", false)
			cloneObj.Set("bodyUsed", false)
			cloneObj.Set("headers", headersObj)
			cloneObj.Set("text", func() interface{} {
				p2, r2, _ := vm.NewPromise()
				r2(vm.ToValue(respBody))
				return vm.ToValue(p2)
			})
			cloneObj.Set("json", func() interface{} {
				p2, r2, rej2 := vm.NewPromise()
				vm.Set("__fetchJsonTmp", respBody)
				jsonVal, jsErr := vm.RunString("JSON.parse(__fetchJsonTmp)")
				vm.Set("__fetchJsonTmp", goja.Undefined())
				if jsErr != nil {
					rej2(vm.ToValue("SyntaxError"))
				} else {
					r2(jsonVal)
				}
				return vm.ToValue(p2)
			})
			return cloneObj
		})

		resolve(vm.ToValue(respObj))
		return vm.ToValue(promise)
	})

	// ── requestIdleCallback / cancelIdleCallback ──
	vm.Set("requestIdleCallback", func(call goja.FunctionCall) goja.Value {
		// Defer to PendingTimers (not synchronous — avoids recursion)
		env.TimerID++
		if !env.TimersFrozen && len(call.Arguments) > 0 {
			if fn, ok := goja.AssertFunction(call.Arguments[0]); ok {
				fnCopy := fn
				env.PendingTimers = append(env.PendingTimers, func() {
					fnCopy(goja.Undefined(), vm.ToValue(map[string]interface{}{
						"didTimeout":    false,
						"timeRemaining": func() float64 { return 50 },
					}))
				})
			}
		}
		return vm.ToValue(env.TimerID)
	})
	vm.Set("cancelIdleCallback", func(id int) {})

	// ── CSS ──
	vm.Set("CSS", map[string]interface{}{
		"supports": func(prop string, value ...string) bool { return false },
		"escape":   func(s string) string { return s },
	})

	// ── getSelection (stub) ──
	vm.Set("getSelection", func() interface{} {
		return map[string]interface{}{
			"anchorNode":   goja.Null(),
			"focusNode":    goja.Null(),
			"anchorOffset": 0,
			"focusOffset":  0,
			"isCollapsed":  true,
			"rangeCount":   0,
			"type":         "None",
			"toString":     func() string { return "" },
			"removeAllRanges": func() {},
			"addRange":     func(r interface{}) {},
			"collapse":     func(node interface{}, offset ...int) {},
			"collapseToStart": func() {},
			"collapseToEnd":   func() {},
			"extend":       func(node interface{}, offset ...int) {},
			"selectAllChildren": func(node interface{}) {},
			"deleteFromDocument": func() {},
			"containsNode": func(node interface{}, allowPartial ...bool) bool { return false },
			"getRangeAt": func(i int) interface{} {
				return map[string]interface{}{
					"startContainer":     goja.Null(),
					"startOffset":        0,
					"endContainer":       goja.Null(),
					"endOffset":          0,
					"collapsed":          true,
					"commonAncestorContainer": goja.Null(),
					"setStart":           func(node, offset interface{}) {},
					"setEnd":             func(node, offset interface{}) {},
					"setStartBefore":     func(node interface{}) {},
					"setStartAfter":      func(node interface{}) {},
					"setEndBefore":       func(node interface{}) {},
					"setEndAfter":        func(node interface{}) {},
					"collapse":           func(toStart bool) {},
					"selectNode":         func(node interface{}) {},
					"selectNodeContents": func(node interface{}) {},
					"deleteContents":     func() {},
					"cloneRange":         func() interface{} { return nil },
					"cloneContents":      func() interface{} { return nil },
					"detach":             func() {},
					"toString":           func() string { return "" },
					"getBoundingClientRect": func() interface{} {
						return map[string]interface{}{
							"top": 0, "right": 0, "bottom": 0, "left": 0,
							"width": 0, "height": 0, "x": 0, "y": 0,
						}
					},
					"getClientRects": func() interface{} { return vm.NewArray() },
				}
			},
		}
	})

	// ── Image / MessageChannel / Worker / SharedWorker — JS constructors ──
	// MessageChannel must actually deliver messages for React scheduler to work.
	vm.RunString(`
		function Image(width, height) {
			this.src = '';
			this.width = width || 0;
			this.height = height || 0;
			this.onload = null;
			this.onerror = null;
			this.addEventListener = function() {};
			this.removeEventListener = function() {};
		}

		function MessagePort() {
			this.onmessage = null;
			this._otherPort = null;
		}
		MessagePort.prototype.postMessage = function(msg) {
			var other = this._otherPort;
			if (other && typeof other.onmessage === 'function') {
				var handler = other.onmessage;
				setTimeout(function() {
					handler({ data: msg, ports: [], target: other });
				}, 0);
			}
		};
		MessagePort.prototype.addEventListener = function(t, fn) {
			if (t === 'message') this.onmessage = fn;
		};
		MessagePort.prototype.removeEventListener = function(t, fn) {
			if (t === 'message' && this.onmessage === fn) this.onmessage = null;
		};
		MessagePort.prototype.close = function() { this.onmessage = null; };
		MessagePort.prototype.start = function() {};

		function MessageChannel() {
			this.port1 = new MessagePort();
			this.port2 = new MessagePort();
			this.port1._otherPort = this.port2;
			this.port2._otherPort = this.port1;
		}

		function Worker(url) {
			this.onmessage = null;
			this.onerror = null;
		}
		Worker.prototype.postMessage = function(msg) {};
		Worker.prototype.terminate = function() {};
		Worker.prototype.addEventListener = function(t, fn) {};
		Worker.prototype.removeEventListener = function(t, fn) {};

		function SharedWorker(url) {
			this.port = new MessagePort();
		}
	`)

	// ── JS-defined polyfills: WeakRef, FinalizationRegistry, Intl, customElements ──
	vm.RunString(`
		// Set polyfill (React uses new Set() for event tracking)
		if (typeof Set === 'undefined') {
			Set = function(iterable) {
				this._items = [];
				if (iterable) {
					for (var i = 0; i < iterable.length; i++) {
						this.add(iterable[i]);
					}
				}
			};
			Set.prototype.has = function(value) {
				return this._items.indexOf(value) !== -1;
			};
			Set.prototype.add = function(value) {
				if (!this.has(value)) this._items.push(value);
				return this;
			};
			Set.prototype.delete = function(value) {
				var idx = this._items.indexOf(value);
				if (idx !== -1) { this._items.splice(idx, 1); return true; }
				return false;
			};
			Set.prototype.clear = function() { this._items = []; };
			Set.prototype.forEach = function(fn, thisArg) {
				for (var i = 0; i < this._items.length; i++) {
					fn.call(thisArg, this._items[i], this._items[i], this);
				}
			};
			Object.defineProperty(Set.prototype, 'size', {
				get: function() { return this._items.length; }
			});
		}

		// Map polyfill (React uses new Map() for fiber tracking)
		if (typeof Map === 'undefined') {
			Map = function() { this._keys = []; this._values = []; };
			Map.prototype.has = function(key) { return this._keys.indexOf(key) !== -1; };
			Map.prototype.get = function(key) {
				var idx = this._keys.indexOf(key);
				return idx !== -1 ? this._values[idx] : undefined;
			};
			Map.prototype.set = function(key, value) {
				var idx = this._keys.indexOf(key);
				if (idx !== -1) { this._values[idx] = value; }
				else { this._keys.push(key); this._values.push(value); }
				return this;
			};
			Map.prototype.delete = function(key) {
				var idx = this._keys.indexOf(key);
				if (idx !== -1) { this._keys.splice(idx, 1); this._values.splice(idx, 1); return true; }
				return false;
			};
			Map.prototype.clear = function() { this._keys = []; this._values = []; };
			Map.prototype.forEach = function(fn, thisArg) {
				for (var i = 0; i < this._keys.length; i++) {
					fn.call(thisArg, this._values[i], this._keys[i], this);
				}
			};
			Object.defineProperty(Map.prototype, 'size', {
				get: function() { return this._keys.length; }
			});
		}

		// WeakRef (stub — goja has no weak references)
		if (typeof WeakRef === 'undefined') {
			WeakRef = function(target) { this._target = target; };
			WeakRef.prototype.deref = function() { return this._target; };
		}

		// FinalizationRegistry (stub)
		if (typeof FinalizationRegistry === 'undefined') {
			FinalizationRegistry = function(callback) { this._callback = callback; };
			FinalizationRegistry.prototype.register = function(target, heldValue, unregisterToken) {};
			FinalizationRegistry.prototype.unregister = function(unregisterToken) {};
		}

		// Intl (minimal stubs)
		if (typeof Intl === 'undefined') {
			var Intl = {};
		}
		if (!Intl.NumberFormat) {
			Intl.NumberFormat = function(locale, opts) {
				this.format = function(n) { return String(n); };
				this.resolvedOptions = function() { return { locale: locale || 'en-US' }; };
			};
		}
		if (!Intl.DateTimeFormat) {
			Intl.DateTimeFormat = function(locale, opts) {
				this.format = function(d) { return d ? d.toString() : ''; };
				this.resolvedOptions = function() { return { locale: locale || 'en-US' }; };
			};
		}
		if (!Intl.Collator) {
			Intl.Collator = function(locale, opts) {
				this.compare = function(a, b) { return a < b ? -1 : a > b ? 1 : 0; };
			};
		}
		if (!Intl.PluralRules) {
			Intl.PluralRules = function(locale, opts) {
				this.select = function(n) { return n === 1 ? 'one' : 'other'; };
			};
		}
		if (!Intl.RelativeTimeFormat) {
			Intl.RelativeTimeFormat = function(locale, opts) {
				this.format = function(value, unit) { return value + ' ' + unit; };
			};
		}

		// customElements (Web Components stub)
		var __customElementsRegistry = {};
		var customElements = {
			define: function(name, cls, opts) { __customElementsRegistry[name] = cls; },
			get: function(name) { return __customElementsRegistry[name]; },
			whenDefined: function(name) { return Promise.resolve(__customElementsRegistry[name]); },
			upgrade: function(root) {}
		};

		// ErrorEvent
		function ErrorEvent(type, init) {
			this.type = type;
			this.message = (init && init.message) || '';
			this.filename = (init && init.filename) || '';
			this.lineno = (init && init.lineno) || 0;
			this.colno = (init && init.colno) || 0;
			this.error = (init && init.error) || null;
		}

		// PromiseRejectionEvent
		function PromiseRejectionEvent(type, init) {
			this.type = type;
			this.promise = (init && init.promise) || null;
			this.reason = (init && init.reason) || null;
		}
	`)

	// ── HTMLElement / Node / DocumentFragment constructors (React instanceof checks) ──
	vm.RunString(`
		// Base Node constructor
		function Node() {}
		Node.ELEMENT_NODE = 1;
		Node.TEXT_NODE = 3;
		Node.COMMENT_NODE = 8;
		Node.DOCUMENT_NODE = 9;
		Node.DOCUMENT_FRAGMENT_NODE = 11;
		Node.prototype.ELEMENT_NODE = 1;
		Node.prototype.TEXT_NODE = 3;
		Node.prototype.COMMENT_NODE = 8;
		Node.prototype.DOCUMENT_NODE = 9;
		Node.prototype.DOCUMENT_FRAGMENT_NODE = 11;

		// Element extends Node
		function Element() {}
		Element.prototype = Object.create(Node.prototype);
		Element.prototype.constructor = Element;

		// HTMLElement extends Element
		function HTMLElement() {}
		HTMLElement.prototype = Object.create(Element.prototype);
		HTMLElement.prototype.constructor = HTMLElement;

		// HTMLDocument
		function HTMLDocument() {}
		HTMLDocument.prototype = Object.create(Node.prototype);
		HTMLDocument.prototype.constructor = HTMLDocument;

		// DocumentFragment
		function DocumentFragment() {}
		DocumentFragment.prototype = Object.create(Node.prototype);
		DocumentFragment.prototype.constructor = DocumentFragment;

		// SVGElement
		function SVGElement() {}
		SVGElement.prototype = Object.create(Element.prototype);
		SVGElement.prototype.constructor = SVGElement;

		// HTMLInputElement, HTMLSelectElement, etc (React checks these)
		function HTMLInputElement() {}
		HTMLInputElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLSelectElement() {}
		HTMLSelectElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLTextAreaElement() {}
		HTMLTextAreaElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLOptionElement() {}
		HTMLOptionElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLFormElement() {}
		HTMLFormElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLAnchorElement() {}
		HTMLAnchorElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLImageElement() {}
		HTMLImageElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLButtonElement() {}
		HTMLButtonElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLDivElement() {}
		HTMLDivElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLSpanElement() {}
		HTMLSpanElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLBodyElement() {}
		HTMLBodyElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLHeadElement() {}
		HTMLHeadElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLStyleElement() {}
		HTMLStyleElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLScriptElement() {}
		HTMLScriptElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLLinkElement() {}
		HTMLLinkElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLMetaElement() {}
		HTMLMetaElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLTableElement() {}
		HTMLTableElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLTableRowElement() {}
		HTMLTableRowElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLTableCellElement() {}
		HTMLTableCellElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLUnknownElement() {}
		HTMLUnknownElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLIFrameElement() {}
		HTMLIFrameElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLLabelElement() {}
		HTMLLabelElement.prototype = Object.create(HTMLElement.prototype);
		function HTMLCanvasElement() {}
		HTMLCanvasElement.prototype = Object.create(HTMLElement.prototype);

		// Sync all HTML constructors to window (React uses window.HTMLIFrameElement etc.)
		if (typeof window !== 'undefined') {
			window.Node = Node;
			window.Element = Element;
			window.HTMLElement = HTMLElement;
			window.HTMLDocument = HTMLDocument;
			window.DocumentFragment = DocumentFragment;
			window.SVGElement = SVGElement;
			window.HTMLInputElement = HTMLInputElement;
			window.HTMLSelectElement = HTMLSelectElement;
			window.HTMLTextAreaElement = HTMLTextAreaElement;
			window.HTMLOptionElement = HTMLOptionElement;
			window.HTMLFormElement = HTMLFormElement;
			window.HTMLAnchorElement = HTMLAnchorElement;
			window.HTMLImageElement = HTMLImageElement;
			window.HTMLButtonElement = HTMLButtonElement;
			window.HTMLDivElement = HTMLDivElement;
			window.HTMLSpanElement = HTMLSpanElement;
			window.HTMLBodyElement = HTMLBodyElement;
			window.HTMLHeadElement = HTMLHeadElement;
			window.HTMLStyleElement = HTMLStyleElement;
			window.HTMLScriptElement = HTMLScriptElement;
			window.HTMLLinkElement = HTMLLinkElement;
			window.HTMLMetaElement = HTMLMetaElement;
			window.HTMLTableElement = HTMLTableElement;
			window.HTMLTableRowElement = HTMLTableRowElement;
			window.HTMLTableCellElement = HTMLTableCellElement;
			window.HTMLUnknownElement = HTMLUnknownElement;
			window.HTMLIFrameElement = HTMLIFrameElement;
			window.HTMLLabelElement = HTMLLabelElement;
			window.HTMLCanvasElement = HTMLCanvasElement;
		}

		// CharacterData (for Text, Comment nodes)
		function CharacterData() {}
		CharacterData.prototype = Object.create(Node.prototype);
		function Text() {}
		Text.prototype = Object.create(CharacterData.prototype);
		function Comment() {}
		Comment.prototype = Object.create(CharacterData.prototype);

		// KeyboardEvent / MouseEvent / FocusEvent / InputEvent / TouchEvent
		function KeyboardEvent(type, init) {
			this.type = type; this.key = (init && init.key) || ''; this.code = (init && init.code) || '';
			this.ctrlKey = (init && init.ctrlKey) || false; this.shiftKey = (init && init.shiftKey) || false;
			this.altKey = (init && init.altKey) || false; this.metaKey = (init && init.metaKey) || false;
			this.bubbles = (init && init.bubbles) || false; this.cancelable = (init && init.cancelable) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
		function MouseEvent(type, init) {
			this.type = type; this.clientX = (init && init.clientX) || 0; this.clientY = (init && init.clientY) || 0;
			this.button = (init && init.button) || 0; this.buttons = (init && init.buttons) || 0;
			this.bubbles = (init && init.bubbles) || false; this.cancelable = (init && init.cancelable) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
		function FocusEvent(type, init) {
			this.type = type; this.relatedTarget = (init && init.relatedTarget) || null;
			this.bubbles = (init && init.bubbles) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
		function InputEvent(type, init) {
			this.type = type; this.data = (init && init.data) || null;
			this.inputType = (init && init.inputType) || '';
			this.bubbles = (init && init.bubbles) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
		function TouchEvent(type, init) {
			this.type = type; this.touches = (init && init.touches) || [];
			this.bubbles = (init && init.bubbles) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
		function AnimationEvent(type, init) {
			this.type = type; this.animationName = (init && init.animationName) || '';
			this.bubbles = (init && init.bubbles) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
		function TransitionEvent(type, init) {
			this.type = type; this.propertyName = (init && init.propertyName) || '';
			this.bubbles = (init && init.bubbles) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
		function UIEvent(type, init) {
			this.type = type; this.detail = (init && init.detail) || 0;
			this.bubbles = (init && init.bubbles) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
		function WheelEvent(type, init) {
			this.type = type; this.deltaX = (init && init.deltaX) || 0; this.deltaY = (init && init.deltaY) || 0;
			this.bubbles = (init && init.bubbles) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
		function ClipboardEvent(type, init) {
			this.type = type;
			this.clipboardData = (init && init.clipboardData) || { getData: function() { return ''; }, setData: function() {} };
			this.bubbles = (init && init.bubbles) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
		function CompositionEvent(type, init) {
			this.type = type; this.data = (init && init.data) || '';
			this.bubbles = (init && init.bubbles) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
		function DragEvent(type, init) {
			this.type = type; this.dataTransfer = (init && init.dataTransfer) || null;
			this.bubbles = (init && init.bubbles) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
		function PopStateEvent(type, init) {
			this.type = type; this.state = (init && init.state) || null;
			this.bubbles = (init && init.bubbles) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
		function HashChangeEvent(type, init) {
			this.type = type; this.newURL = (init && init.newURL) || ''; this.oldURL = (init && init.oldURL) || '';
			this.bubbles = (init && init.bubbles) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
		function PageTransitionEvent(type, init) {
			this.type = type; this.persisted = (init && init.persisted) || false;
			this.bubbles = (init && init.bubbles) || false;
			this.preventDefault = function() {}; this.stopPropagation = function() {};
		}
	`)

	// ── Bridge: sync VM globals onto window object ──
	// React checks window.requestAnimationFrame, window.setTimeout, etc.
	vm.RunString(`
		(function() {
			var globals = [
				// JS built-in globals (webpack's global polyfill checks e.Math === Math)
				'Math', 'JSON', 'Object', 'Array', 'String', 'Number', 'Boolean', 'Date',
				'RegExp', 'Error', 'TypeError', 'RangeError', 'SyntaxError', 'ReferenceError',
				'Map', 'Set', 'WeakMap', 'WeakSet', 'Promise', 'Symbol', 'Proxy', 'Reflect',
				'parseInt', 'parseFloat', 'isNaN', 'isFinite', 'NaN', 'Infinity',
				'encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI',
				'ArrayBuffer', 'DataView', 'Int8Array', 'Uint8Array', 'Float32Array', 'Float64Array',
				// Timer/RAF functions
				'requestAnimationFrame', 'cancelAnimationFrame',
				'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval',
				'queueMicrotask', 'requestIdleCallback', 'cancelIdleCallback',
				'fetch', 'getComputedStyle', 'matchMedia', 'getSelection',
				'atob', 'btoa', 'structuredClone',
				'MutationObserver', 'ResizeObserver', 'IntersectionObserver', 'PerformanceObserver',
				'AbortController', 'AbortSignal', 'DOMException',
				'URL', 'URLSearchParams', 'Headers', 'Request', 'Response',
				'TextEncoder', 'TextDecoder', 'Blob', 'File', 'FormData',
				'XMLHttpRequest', 'DOMParser', 'Image', 'MessageChannel', 'Worker', 'SharedWorker',
				'Node', 'Element', 'HTMLElement', 'HTMLDocument', 'DocumentFragment', 'SVGElement',
				'Event', 'CustomEvent', 'KeyboardEvent', 'MouseEvent', 'FocusEvent', 'InputEvent',
				'TouchEvent', 'AnimationEvent', 'TransitionEvent', 'UIEvent', 'WheelEvent',
				'ClipboardEvent', 'CompositionEvent', 'DragEvent', 'PopStateEvent',
				'ErrorEvent', 'PromiseRejectionEvent',
				'WeakRef', 'FinalizationRegistry',
				'performance', 'navigator', 'location', 'document', 'console',
				'localStorage', 'sessionStorage', 'crypto', 'CSS',
				'customElements', 'process'
			];
			for (var i = 0; i < globals.length; i++) {
				var name = globals[i];
				try {
					var val = eval(name);
					if (typeof val !== 'undefined' && window[name] === undefined) {
						window[name] = val;
					}
				} catch(e) {}
			}
		})();
	`)
}

func (env *BrowserEnv) createDocumentObject() map[string]interface{} {
	doc := env.Doc

	// Document-level event target for React's event delegation
	if doc.Root.Events == nil {
		doc.Root.Events = NewEventTarget()
	}

	docObj := map[string]interface{}{
		// ── Node identity (React checks document.nodeType === 9) ──
		"nodeType": 9,
		"nodeName": "#document",

		// ── Event methods (React 17+ delegates events to document/container) ──
		"addEventListener": func(eventType string, handler interface{}, opts ...interface{}) {
			doc.Root.Events.AddEventListener(eventType, handler)
		},
		"removeEventListener": func(eventType string, handler interface{}) {
			doc.Root.Events.RemoveEventListener(eventType, handler)
		},
		"dispatchEvent": func(call goja.FunctionCall) goja.Value {
			return env.VM.ToValue(true)
		},

		// ── Query ──
		"getElementById": func(id string) interface{} {
			node := doc.QuerySelector("#" + id)
			if node == nil {
				return goja.Null()
			}
			return env.WrapNode(node)
		},
		"getElementsByTagName": func(tag string) interface{} {
			nodes := doc.Root.GetElementsByTagName(tag)
			return env.wrapNodeList(nodes)
		},
		"getElementsByClassName": func(cls string) interface{} {
			sel := "." + strings.ReplaceAll(cls, " ", ".")
			nodes := doc.Root.QuerySelectorAll(sel)
			return env.wrapNodeList(nodes)
		},
		"querySelector": func(sel string) interface{} {
			node := doc.QuerySelector(sel)
			if node == nil {
				return goja.Null()
			}
			return env.WrapNode(node)
		},
		"querySelectorAll": func(sel string) interface{} {
			nodes := doc.Root.QuerySelectorAll(sel)
			return env.wrapNodeList(nodes)
		},

		// ── Creation ──
		"createElement": func(tag string) interface{} {
			node := NewElement(strings.ToLower(tag))
			return env.WrapNode(node)
		},
		"createTextNode": func(text string) interface{} {
			node := &Node{
				Type:  TextNode,
				Text:  text,
				Attrs: make(map[string]string),
			}
			return env.WrapNode(node)
		},
		"createDocumentFragment": func() interface{} {
			node := &Node{
				Type:     DocumentNode,
				Tag:      "#document-fragment",
				Children: make([]*Node, 0),
				Attrs:    make(map[string]string),
			}
			return env.WrapNode(node)
		},
		"createComment": func(text string) interface{} {
			node := &Node{
				Type:  CommentNode,
				Text:  text,
				Attrs: make(map[string]string),
			}
			return env.WrapNode(node)
		},
		"createEvent": func(eventType string) interface{} {
			return (&DOMEvent{Type: eventType}).ToMap()
		},
		"createElementNS": func(ns, tag string) interface{} {
			node := NewElement(strings.ToLower(tag))
			node.Namespace = ns
			return env.WrapNode(node)
		},

		// ── Properties ──
		"readyState":      "complete",
		"compatMode":      "CSS1Compat",
		"activeElement":   func() interface{} { return env.getBodyWrapped() },
		"hidden":          false,
		"visibilityState": "visible",
		"characterSet":    "UTF-8",
		"charset":         "UTF-8",
		"contentType":     "text/html",
		"domain":          urlPart(doc.URL, "hostname"),
		"referrer":        "",

		// ── Cookie ──
		"cookie": "", // getter/setter handled via methods

		// ── Implementation stubs ──
		"createRange": func() interface{} {
			return map[string]interface{}{
				"collapsed":            true,
				"startOffset":          0,
				"endOffset":            0,
				"commonAncestorContainer": goja.Null(),
				"setStart":             func(node, offset interface{}) {},
				"setEnd":               func(node, offset interface{}) {},
				"setStartBefore":       func(node interface{}) {},
				"setStartAfter":        func(node interface{}) {},
				"setEndBefore":         func(node interface{}) {},
				"setEndAfter":          func(node interface{}) {},
				"selectNode":           func(node interface{}) {},
				"selectNodeContents":   func(node interface{}) {},
				"collapse":             func(toStart ...bool) {},
				"insertNode":           func(node interface{}) {},
				"deleteContents":       func() {},
				"extractContents":      func() interface{} { return nil },
				"cloneContents":        func() interface{} { return nil },
				"cloneRange":           func() interface{} { return nil },
				"detach":               func() {},
				"toString":             func() string { return "" },
				"getBoundingClientRect": func() interface{} {
					return map[string]interface{}{
						"top": 0, "right": 0, "bottom": 0, "left": 0,
						"width": 0, "height": 0, "x": 0, "y": 0,
					}
				},
				"getClientRects": func() interface{} { return []interface{}{} },
				"createContextualFragment": func(html string) interface{} {
					frags, _ := ParseFragment(html)
					if len(frags) > 0 {
						return env.WrapNode(frags[0])
					}
					return nil
				},
			}
		},
		"createTreeWalker": func(root, whatToShow interface{}, filter ...interface{}) interface{} {
			return map[string]interface{}{
				"root":           root,
				"whatToShow":     whatToShow,
				"currentNode":   root,
				"filter":        goja.Null(),
				"nextNode":      func() interface{} { return goja.Null() },
				"previousNode":  func() interface{} { return goja.Null() },
				"firstChild":    func() interface{} { return goja.Null() },
				"lastChild":     func() interface{} { return goja.Null() },
				"nextSibling":   func() interface{} { return goja.Null() },
				"previousSibling": func() interface{} { return goja.Null() },
				"parentNode":    func() interface{} { return goja.Null() },
			}
		},
		"implementation": map[string]interface{}{
			"createHTMLDocument": func(title string) interface{} {
				return env.createDocumentObject()
			},
		},
	}

	// Dynamic body/head getters (lazy)
	docObj["body"] = func() interface{} { return env.getBodyWrapped() }
	docObj["head"] = func() interface{} { return env.getHeadWrapped() }

	// title getter
	docObj["title"] = doc.Title()

	return docObj
}

func (env *BrowserEnv) createWindowObject(documentObj map[string]interface{}) *goja.Object {
	vm := env.VM
	doc := env.Doc

	win := vm.NewObject()
	win.Set("document", documentObj)
	win.Set("location", env.createLocationObject())
	win.Set("navigator", vm.Get("navigator"))
	win.Set("history", map[string]interface{}{
		"pushState":    func(state, title interface{}, url string) {},
		"replaceState": func(state, title interface{}, url string) {},
		"back":         func() {},
		"forward":      func() {},
		"go":           func(delta int) {},
		"length":       1,
		"state":        nil,
	})
	win.Set("localStorage", doc.Storage.AsMap())
	win.Set("sessionStorage", doc.Storage.AsMap())
	win.Set("innerWidth", doc.ViewportW)
	win.Set("innerHeight", doc.ViewportH)
	win.Set("outerWidth", doc.ViewportW)
	win.Set("outerHeight", doc.ViewportH)
	// Screen values — fingerprint-aware with fallback defaults
	screenW := 1920
	screenH := 1080
	colorDepth := 24
	pixelRatio := 1.0
	if env.Fingerprint != nil {
		if env.Fingerprint.ScreenWidth > 0 {
			screenW = env.Fingerprint.ScreenWidth
		}
		if env.Fingerprint.ScreenHeight > 0 {
			screenH = env.Fingerprint.ScreenHeight
		}
		if env.Fingerprint.ColorDepth > 0 {
			colorDepth = env.Fingerprint.ColorDepth
		}
		if env.Fingerprint.PixelRatio > 0 {
			pixelRatio = env.Fingerprint.PixelRatio
		}
	}
	win.Set("screen", map[string]interface{}{
		"width":       screenW,
		"height":      screenH,
		"availWidth":  screenW,
		"availHeight": screenH - 40,
		"colorDepth":  colorDepth,
		"pixelDepth":  colorDepth,
	})
	win.Set("devicePixelRatio", pixelRatio)
	win.Set("scrollX", 0)
	win.Set("scrollY", 0)
	win.Set("pageXOffset", 0)
	win.Set("pageYOffset", 0)
	win.Set("scrollTo", func(x, y int) {})
	win.Set("scroll", func(x, y int) {})
	win.Set("scrollBy", func(x, y int) {})
	win.Set("addEventListener", func(t string, fn interface{}, opts ...interface{}) {})
	win.Set("removeEventListener", func(t string, fn interface{}) {})
	win.Set("dispatchEvent", func(event interface{}) bool { return true })
	win.Set("open", func(url string, target ...string) interface{} {
		// Return a minimal window proxy object like a real browser
		fakeWin := vm.NewObject()
		fakeWin.Set("closed", false)
		fakeWin.Set("opener", win)
		fakeWin.Set("location", map[string]interface{}{"href": url})
		fakeWin.Set("close", func() { fakeWin.Set("closed", true) })
		fakeWin.Set("focus", func() {})
		fakeWin.Set("blur", func() {})
		fakeWin.Set("postMessage", func(msg, origin interface{}) {})
		fakeWin.Set("document", map[string]interface{}{
			"write":  func(html string) {},
			"close":  func() {},
			"open":   func() {},
		})
		fakeWin.Set("name", func() string {
			if len(target) > 0 { return target[0] }
			return ""
		}())
		return fakeWin
	})
	win.Set("close", func() {})
	win.Set("print", func() {})
	win.Set("alert", func(msg string) { fmt.Printf("[alert] %s\n", msg) })
	win.Set("confirm", func(msg string) bool { return true })
	win.Set("prompt", func(msg string, def ...string) string {
		if len(def) > 0 {
			return def[0]
		}
		return ""
	})
	win.Set("postMessage", func(msg, origin interface{}) {})
	win.Set("focus", func() {})
	win.Set("blur", func() {})
	win.Set("getSelection", func() interface{} { return vm.Get("getSelection") })
	win.Set("self", win)
	win.Set("top", win)
	win.Set("parent", win)
	win.Set("frames", win)
	win.Set("frameElement", goja.Null())
	win.Set("length", 0)
	win.Set("closed", false)
	win.Set("name", "")
	win.Set("opener", goja.Null())
	win.Set("isSecureContext", true)

	return win
}

func (env *BrowserEnv) createLocationObject() *goja.Object {
	vm := env.VM
	doc := env.Doc

	loc := vm.NewObject()
	loc.Set("href", doc.URL)
	loc.Set("protocol", urlPart(doc.URL, "protocol"))
	loc.Set("host", urlPart(doc.URL, "host"))
	loc.Set("hostname", urlPart(doc.URL, "hostname"))
	loc.Set("port", urlPart(doc.URL, "port"))
	loc.Set("pathname", urlPart(doc.URL, "pathname"))
	loc.Set("search", urlPart(doc.URL, "search"))
	loc.Set("hash", "")
	loc.Set("origin", urlPart(doc.URL, "origin"))
	loc.Set("assign", func(url string) {})
	loc.Set("replace", func(url string) {})
	loc.Set("reload", func() {})
	loc.Set("toString", func() string { return doc.URL })
	return loc
}

func urlPart(rawURL, part string) string {
	if rawURL == "" {
		return ""
	}
	// Simple URL parsing
	protoIdx := strings.Index(rawURL, "://")
	if protoIdx == -1 {
		return ""
	}
	protocol := rawURL[:protoIdx+1] // "https:"
	rest := rawURL[protoIdx+3:]     // "www.example.com/path?query"

	pathIdx := strings.Index(rest, "/")
	host := rest
	pathAndQuery := "/"
	if pathIdx >= 0 {
		host = rest[:pathIdx]
		pathAndQuery = rest[pathIdx:]
	}

	hostname := host
	port := ""
	if colonIdx := strings.LastIndex(host, ":"); colonIdx >= 0 {
		hostname = host[:colonIdx]
		port = host[colonIdx+1:]
	}

	searchIdx := strings.Index(pathAndQuery, "?")
	pathname := pathAndQuery
	search := ""
	if searchIdx >= 0 {
		pathname = pathAndQuery[:searchIdx]
		search = pathAndQuery[searchIdx:]
	}

	switch part {
	case "protocol":
		return protocol
	case "host":
		return host
	case "hostname":
		return hostname
	case "port":
		return port
	case "pathname":
		return pathname
	case "search":
		return search
	case "origin":
		return protocol + "//" + host
	}
	return ""
}

func (env *BrowserEnv) getBodyWrapped() interface{} {
	bodyNode := env.Doc.Body()
	if bodyNode == nil {
		return nil
	}
	return env.WrapNode(bodyNode)
}

func (env *BrowserEnv) getHeadWrapped() interface{} {
	headNode := env.Doc.findTag("head")
	if headNode == nil {
		return nil
	}
	return env.WrapNode(headNode)
}
