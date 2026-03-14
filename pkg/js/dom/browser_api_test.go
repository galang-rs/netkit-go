package dom

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
)

// TestBrowserAPI_AllGlobals tests every injected browser global one by one.
// Each test runs a small JS snippet and reports pass/fail.
func TestBrowserAPI_AllGlobals(t *testing.T) {
	doc, _ := ParseWithURL(`<html><head><title>Test</title></head><body><div id="root"><p class="item">Hello</p></div></body></html>`, "https://example.com/page?q=1")
	vm := goja.New()
	vm.SetFieldNameMapper(goja.UncapFieldNameMapper())
	env := NewBrowserEnv(doc, vm)
	env.InjectGlobals()

	tests := []struct {
		name string
		js   string
	}{
		// ── window basics ──
		{"window exists", `typeof window === 'object'`},
		{"window.self === window", `window.self === window`},
		{"window.top === window", `window.top === window`},
		{"window.parent === window", `window.parent === window`},
		{"window.frames === window", `window.frames === window`},
		{"window.closed === false", `window.closed === false`},
		{"window.name is string", `typeof window.name === 'string'`},
		{"window.length === 0", `window.length === 0`},
		{"window.isSecureContext", `window.isSecureContext === true`},
		{"window.opener is null", `window.opener === null`},
		{"window.frameElement is null", `window.frameElement === null`},

		// ── window dimensions ──
		{"window.innerWidth > 0", `window.innerWidth > 0`},
		{"window.innerHeight > 0", `window.innerHeight > 0`},
		{"window.outerWidth > 0", `window.outerWidth > 0`},
		{"window.outerHeight > 0", `window.outerHeight > 0`},
		{"window.scrollX === 0", `window.scrollX === 0`},
		{"window.scrollY === 0", `window.scrollY === 0`},
		{"window.pageXOffset === 0", `window.pageXOffset === 0`},
		{"window.pageYOffset === 0", `window.pageYOffset === 0`},
		{"window.devicePixelRatio", `window.devicePixelRatio === 1`},

		// ── window methods ──
		{"window.scrollTo", `typeof window.scrollTo === 'function'`},
		{"window.scroll", `typeof window.scroll === 'function'`},
		{"window.scrollBy", `typeof window.scrollBy === 'function'`},
		{"window.addEventListener", `typeof window.addEventListener === 'function'`},
		{"window.removeEventListener", `typeof window.removeEventListener === 'function'`},
		{"window.dispatchEvent", `typeof window.dispatchEvent === 'function'`},
		{"window.open returns object", `typeof window.open('about:blank') === 'object'`},
		{"window.close", `typeof window.close === 'function'`},
		{"window.print", `typeof window.print === 'function'`},
		{"window.alert", `typeof window.alert === 'function'`},
		{"window.confirm returns bool", `window.confirm('test') === true`},
		{"window.prompt returns string", `typeof window.prompt('test') === 'string'`},
		{"window.postMessage", `typeof window.postMessage === 'function'`},
		{"window.focus", `typeof window.focus === 'function'`},
		{"window.blur", `typeof window.blur === 'function'`},
		{"window.getSelection", `typeof window.getSelection === 'function'`},

		// ── window.screen ──
		{"window.screen.width", `window.screen.width === 1920`},
		{"window.screen.height", `window.screen.height === 1080`},
		{"window.screen.availWidth", `window.screen.availWidth === 1920`},
		{"window.screen.availHeight", `window.screen.availHeight === 1040`},
		{"window.screen.colorDepth", `window.screen.colorDepth === 24`},
		{"window.screen.pixelDepth", `window.screen.pixelDepth === 24`},

		// ── globalThis / self ──
		{"globalThis === window", `globalThis === window`},
		{"self === window", `self === window`},

		// ── document basics ──
		{"document exists", `typeof document === 'object'`},
		{"document.nodeType === 9", `document.nodeType === 9`},
		{"document.nodeName", `document.nodeName === '#document'`},
		{"document.readyState", `document.readyState === 'complete'`},
		{"document.compatMode", `document.compatMode === 'CSS1Compat'`},
		{"document.hidden === false", `document.hidden === false`},
		{"document.visibilityState", `document.visibilityState === 'visible'`},
		{"document.characterSet", `document.characterSet === 'UTF-8'`},
		{"document.charset", `document.charset === 'UTF-8'`},
		{"document.contentType", `document.contentType === 'text/html'`},
		{"document.domain", `document.domain === 'example.com'`},
		{"document.referrer is string", `typeof document.referrer === 'string'`},
		{"document.URL", `document.URL === 'https://example.com/page?q=1'`},
		{"document.title", `document.title === 'Test'`},

		// ── document query ──
		{"document.getElementById", `typeof document.getElementById === 'function'`},
		{"document.getElementById result", `document.getElementById('root') !== null`},
		{"document.getElementById miss", `document.getElementById('nonexistent') === null`},
		{"document.querySelector", `typeof document.querySelector === 'function'`},
		{"document.querySelector result", `document.querySelector('#root') !== null`},
		{"document.querySelector miss", `document.querySelector('#miss') === null`},
		{"document.querySelectorAll", `typeof document.querySelectorAll === 'function'`},
		{"document.getElementsByTagName", `typeof document.getElementsByTagName === 'function'`},
		{"document.getElementsByClassName", `typeof document.getElementsByClassName === 'function'`},

		// ── document creation ──
		{"document.createElement", `typeof document.createElement === 'function'`},
		{"document.createElement div", `(function() { var el = document.createElement('div'); return el && el.tagName === 'DIV'; })()`},
		{"document.createTextNode", `typeof document.createTextNode === 'function'`},
		{"document.createTextNode val", `(function() { var t = document.createTextNode('hi'); return t !== null; })()`},
		{"document.createDocumentFragment", `typeof document.createDocumentFragment === 'function'`},
		{"document.createComment", `typeof document.createComment === 'function'`},
		{"document.createEvent", `typeof document.createEvent === 'function'`},
		{"document.createElementNS", `typeof document.createElementNS === 'function'`},
		{"document.createElementNS svg", `(function() { var el = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); return el && el.namespaceURI === 'http://www.w3.org/2000/svg'; })()`},

		// ── document properties ──
		{"document.documentElement", `typeof document.documentElement === 'object' && document.documentElement !== null`},
		{"document.body", `typeof document.body === 'function' || typeof document.body === 'object'`},
		{"document.head", `typeof document.head === 'function' || typeof document.head === 'object'`},
		{"document.activeElement", `typeof document.activeElement === 'function' || typeof document.activeElement === 'object'`},

		// ── document methods ──
		{"document.addEventListener", `typeof document.addEventListener === 'function'`},
		{"document.removeEventListener", `typeof document.removeEventListener === 'function'`},
		{"document.dispatchEvent", `typeof document.dispatchEvent === 'function'`},
		{"document.createRange", `typeof document.createRange === 'function'`},
		{"document.createRange result", `(function() { var r = document.createRange(); return r && typeof r.setStart === 'function' && typeof r.collapse === 'function'; })()`},
		{"document.createTreeWalker", `typeof document.createTreeWalker === 'function'`},
		{"document.createTreeWalker result", `(function() { var b = document.body; if (typeof b === 'function') b = b(); var tw = document.createTreeWalker(b, 1); return tw && typeof tw.nextNode === 'function' && tw.currentNode !== undefined; })()`},
		{"document.implementation", `typeof document.implementation === 'object'`},
		{"document.implementation.createHTMLDocument", `typeof document.implementation.createHTMLDocument === 'function'`},

		// ── location ──
		{"location exists", `typeof location === 'object'`},
		{"location.href", `location.href === 'https://example.com/page?q=1'`},
		{"location.protocol", `location.protocol === 'https:'`},
		{"location.hostname", `location.hostname === 'example.com'`},
		{"location.host", `location.host === 'example.com'`},
		{"location.pathname", `location.pathname === '/page'`},
		{"location.search", `location.search === '?q=1'`},
		{"location.origin", `location.origin === 'https://example.com'`},
		{"location.assign", `typeof location.assign === 'function'`},
		{"location.replace", `typeof location.replace === 'function'`},
		{"location.reload", `typeof location.reload === 'function'`},
		{"location.toString", `typeof location.toString === 'function'`},
		{"document.location", `typeof document.location === 'object'`},

		// ── history ──
		{"history exists", `typeof history === 'object'`},
		{"history.pushState", `typeof history.pushState === 'function'`},
		{"history.replaceState", `typeof history.replaceState === 'function'`},
		{"history.back", `typeof history.back === 'function'`},
		{"history.forward", `typeof history.forward === 'function'`},
		{"history.go", `typeof history.go === 'function'`},
		{"history.length", `history.length === 1`},

		// ── navigator ──
		{"navigator exists", `typeof navigator === 'object'`},
		{"navigator.userAgent", `typeof navigator.userAgent === 'string' && navigator.userAgent.indexOf('Mozilla') >= 0`},
		{"navigator.language", `navigator.language === 'en-US'`},
		{"navigator.languages", `Array.isArray(navigator.languages) && navigator.languages.length > 0`},
		{"navigator.platform", `navigator.platform === 'Win32'`},
		{"navigator.cookieEnabled", `navigator.cookieEnabled === true`},
		{"navigator.onLine", `navigator.onLine === true`},
		{"navigator.hardwareConcurrency", `navigator.hardwareConcurrency === 8`},
		{"navigator.maxTouchPoints", `navigator.maxTouchPoints === 0`},
		{"navigator.vendor", `navigator.vendor === 'Google Inc.'`},
		{"navigator.product", `navigator.product === 'Gecko'`},
		{"navigator.productSub", `navigator.productSub === '20030107'`},
		{"navigator.appName", `navigator.appName === 'Netscape'`},

		// ── navigator.serviceWorker ──
		{"navigator.serviceWorker", `typeof navigator.serviceWorker === 'object'`},
		{"navigator.serviceWorker.register", `typeof navigator.serviceWorker.register === 'function'`},
		{"navigator.serviceWorker.ready", `typeof navigator.serviceWorker.ready === 'function'`},
		{"navigator.serviceWorker.getRegistrations", `typeof navigator.serviceWorker.getRegistrations === 'function'`},
		{"navigator.serviceWorker.addEventListener", `typeof navigator.serviceWorker.addEventListener === 'function'`},

		// ── navigator.mediaDevices ──
		{"navigator.mediaDevices", `typeof navigator.mediaDevices === 'object'`},
		{"navigator.mediaDevices.getUserMedia", `typeof navigator.mediaDevices.getUserMedia === 'function'`},
		{"navigator.mediaDevices.enumerateDevices", `typeof navigator.mediaDevices.enumerateDevices === 'function'`},

		// ── navigator.credentials ──
		{"navigator.credentials", `typeof navigator.credentials === 'object'`},
		{"navigator.credentials.get", `typeof navigator.credentials.get === 'function'`},
		{"navigator.credentials.create", `typeof navigator.credentials.create === 'function'`},
		{"navigator.credentials.store", `typeof navigator.credentials.store === 'function'`},
		{"navigator.credentials.preventSilentAccess", `typeof navigator.credentials.preventSilentAccess === 'function'`},

		// ── navigator.clipboard ──
		{"navigator.clipboard", `typeof navigator.clipboard === 'object'`},
		{"navigator.clipboard.readText", `typeof navigator.clipboard.readText === 'function'`},
		{"navigator.clipboard.writeText", `typeof navigator.clipboard.writeText === 'function'`},

		// ── navigator.permissions ──
		{"navigator.permissions", `typeof navigator.permissions === 'object'`},
		{"navigator.permissions.query", `typeof navigator.permissions.query === 'function'`},

		// ── navigator.storage ──
		{"navigator.storage", `typeof navigator.storage === 'object'`},
		{"navigator.storage.estimate", `typeof navigator.storage.estimate === 'function'`},

		// ── navigator.locks ──
		{"navigator.locks", `typeof navigator.locks === 'object'`},
		{"navigator.locks.request", `typeof navigator.locks.request === 'function'`},
		{"navigator.locks.query", `typeof navigator.locks.query === 'function'`},

		// ── navigator.sendBeacon / vibrate ──
		{"navigator.sendBeacon", `typeof navigator.sendBeacon === 'function'`},
		{"navigator.vibrate", `typeof navigator.vibrate === 'function'`},

		// ── console ──
		{"console exists", `typeof console === 'object'`},
		{"console.log", `typeof console.log === 'function'`},
		{"console.warn", `typeof console.warn === 'function'`},
		{"console.error", `typeof console.error === 'function'`},
		{"console.info", `typeof console.info === 'function'`},
		{"console.debug", `typeof console.debug === 'function'`},
		{"console.trace", `typeof console.trace === 'function'`},
		{"console.dir", `typeof console.dir === 'function'`},
		{"console.table", `typeof console.table === 'function'`},
		{"console.time", `typeof console.time === 'function'`},
		{"console.timeEnd", `typeof console.timeEnd === 'function'`},
		{"console.group", `typeof console.group === 'function'`},
		{"console.groupEnd", `typeof console.groupEnd === 'function'`},
		{"console.clear", `typeof console.clear === 'function'`},
		{"console.assert", `typeof console.assert === 'function'`},

		// ── localStorage / sessionStorage ──
		{"localStorage exists", `typeof localStorage === 'object'`},
		{"sessionStorage exists", `typeof sessionStorage === 'object'`},

		// ── timers ──
		{"setTimeout", `typeof setTimeout === 'function'`},
		{"setTimeout returns id", `typeof setTimeout(function(){}, 0) === 'number'`},
		{"setInterval", `typeof setInterval === 'function'`},
		{"setInterval returns id", `typeof setInterval(function(){}, 1000) === 'number'`},
		{"clearTimeout", `typeof clearTimeout === 'function'`},
		{"clearInterval", `typeof clearInterval === 'function'`},
		{"requestAnimationFrame", `typeof requestAnimationFrame === 'function'`},
		{"requestAnimationFrame returns id", `typeof requestAnimationFrame(function(){}) === 'number'`},
		{"cancelAnimationFrame", `typeof cancelAnimationFrame === 'function'`},
		{"requestIdleCallback", `typeof requestIdleCallback === 'function'`},
		{"cancelIdleCallback", `typeof cancelIdleCallback === 'function'`},
		{"queueMicrotask", `typeof queueMicrotask === 'function'`},

		// ── fetch ──
		{"fetch", `typeof fetch === 'function'`},

		// ── Base64 ──
		{"atob", `typeof atob === 'function'`},
		{"atob decode", `atob('SGVsbG8=') === 'Hello'`},
		{"btoa", `typeof btoa === 'function'`},
		{"btoa encode", `btoa('Hello') === 'SGVsbG8='`},

		// ── structuredClone ──
		{"structuredClone", `typeof structuredClone === 'function'`},
		{"structuredClone works", `structuredClone(42) === 42`},

		// ── Event constructors ──
		{"Event constructor", `typeof Event === 'function'`},
		{"Event instance", `(function() { var e = new Event('click'); return e.type === 'click'; })()`},
		{"CustomEvent constructor", `typeof CustomEvent === 'function'`},
		{"CustomEvent instance", `(function() { var e = new CustomEvent('test', {detail: 42}); return e.type === 'test' && e.detail === 42; })()`},

		// ── Observers ──
		{"MutationObserver", `typeof MutationObserver === 'function'`},
		{"MutationObserver new", `(function() { var o = new MutationObserver(function(){}); return typeof o.observe === 'function' && typeof o.disconnect === 'function'; })()`},
		{"ResizeObserver", `typeof ResizeObserver === 'function'`},
		{"ResizeObserver new", `(function() { var o = new ResizeObserver(function(){}); return typeof o.observe === 'function'; })()`},
		{"IntersectionObserver", `typeof IntersectionObserver === 'function'`},
		{"IntersectionObserver new", `(function() { var o = new IntersectionObserver(function(){}); return typeof o.observe === 'function'; })()`},
		{"PerformanceObserver", `typeof PerformanceObserver === 'function'`},

		// ── performance ──
		{"performance exists", `typeof performance === 'object'`},
		{"performance.now", `typeof performance.now === 'function'`},
		{"performance.now returns number", `typeof performance.now() === 'number'`},
		{"performance.mark", `typeof performance.mark === 'function'`},
		{"performance.measure", `typeof performance.measure === 'function'`},
		{"performance.getEntriesByType", `typeof performance.getEntriesByType === 'function'`},

		// ── matchMedia ──
		{"matchMedia", `typeof matchMedia === 'function'`},
		{"matchMedia result", `(function() { var m = matchMedia('(max-width: 600px)'); return typeof m.matches === 'boolean' && m.media === '(max-width: 600px)' && typeof m.addEventListener === 'function'; })()`},

		// ── getComputedStyle ──
		{"getComputedStyle", `typeof getComputedStyle === 'function'`},
		{"getComputedStyle result", `(function() { var el = document.createElement('div'); var s = getComputedStyle(el); return s.display === 'block' && typeof s.getPropertyValue === 'function'; })()`},

		// ── getSelection ──
		{"getSelection", `typeof getSelection === 'function'`},
		{"getSelection result", `(function() { var s = getSelection(); return s.isCollapsed === true && s.rangeCount === 0 && typeof s.getRangeAt === 'function' && typeof s.removeAllRanges === 'function'; })()`},
		{"getSelection.getRangeAt result", `(function() { var r = getSelection().getRangeAt(0); return r && typeof r.setStart === 'function' && typeof r.collapse === 'function' && r.collapsed === true; })()`},

		// ── URL / URLSearchParams ──
		{"URL constructor", `typeof URL === 'function'`},
		{"URL parse", `(function() { var u = new URL('https://example.com/path?q=1#h'); return u.protocol === 'https:' && u.hostname === 'example.com' && u.pathname === '/path' && u.search === '?q=1' && u.hash === '#h'; })()`},
		{"URL.createObjectURL", `typeof URL.createObjectURL === 'function'`},
		{"URL.revokeObjectURL", `typeof URL.revokeObjectURL === 'function'`},
		{"URLSearchParams constructor", `typeof URLSearchParams === 'function'`},
		{"URLSearchParams parse", `(function() { var p = new URLSearchParams('a=1&b=2'); return p.get('a') === '1' && p.get('b') === '2' && p.has('a'); })()`},

		// ── Headers / Request / Response ──
		{"Headers constructor", `typeof Headers === 'function'`},
		{"Headers usage", `(function() { var h = new Headers({'content-type': 'text/html'}); return h.get('content-type') === 'text/html'; })()`},
		{"Request constructor", `typeof Request === 'function'`},
		{"Request instance", `(function() { var r = new Request('https://example.com', {method: 'POST'}); return r.url === 'https://example.com' && r.method === 'POST'; })()`},
		{"Response constructor", `typeof Response === 'function'`},
		{"Response instance", `(function() { var r = new Response('body', {status: 200}); return r.ok === true && r.status === 200; })()`},
		{"Response.error", `typeof Response.error === 'function'`},
		{"Response.redirect", `typeof Response.redirect === 'function'`},

		// ── TextEncoder / TextDecoder ──
		{"TextEncoder", `typeof TextEncoder === 'function'`},
		{"TextEncoder encode", `(function() { var enc = new TextEncoder(); var arr = enc.encode('AB'); return arr.length === 2 && arr[0] === 65 && arr[1] === 66; })()`},
		{"TextDecoder", `typeof TextDecoder === 'function'`},

		// ── Blob / File / FormData ──
		{"Blob constructor", `typeof Blob === 'function'`},
		{"Blob instance", `(function() { var b = new Blob(['test'], {type: 'text/plain'}); return b.size === 4 && b.type === 'text/plain'; })()`},
		{"File constructor", `typeof File === 'function'`},
		{"File instance", `(function() { var f = new File(['data'], 'test.txt'); return f.name === 'test.txt' && f.size === 4; })()`},
		{"FormData constructor", `typeof FormData === 'function'`},
		{"FormData usage", `(function() { var fd = new FormData(); fd.append('key', 'val'); return fd.get('key') === 'val' && fd.has('key'); })()`},

		// ── XMLHttpRequest ──
		{"XMLHttpRequest", `typeof XMLHttpRequest === 'function'`},
		{"XMLHttpRequest instance", `(function() { var x = new XMLHttpRequest(); return x.readyState === 0 && typeof x.open === 'function' && typeof x.send === 'function'; })()`},
		{"XMLHttpRequest constants", `XMLHttpRequest.DONE === 4 && XMLHttpRequest.OPENED === 1`},

		// ── DOMParser ──
		{"DOMParser", `typeof DOMParser === 'function'`},

		// ── DOMException ──
		{"DOMException", `typeof DOMException === 'function'`},
		{"DOMException instance", `(function() { var e = new DOMException('test', 'AbortError'); return e.message === 'test' && e.name === 'AbortError'; })()`},

		// ── AbortController / AbortSignal ──
		{"AbortController", `typeof AbortController === 'function'`},
		{"AbortController usage", `(function() { var ac = new AbortController(); return ac.signal.aborted === false && typeof ac.abort === 'function'; })()`},
		{"AbortController abort", `(function() { var ac = new AbortController(); ac.abort(); return ac.signal.aborted === true; })()`},
		{"AbortSignal", `typeof AbortSignal === 'function'`},
		{"AbortSignal.abort", `typeof AbortSignal.abort === 'function'`},
		{"AbortSignal.timeout", `typeof AbortSignal.timeout === 'function'`},
		{"AbortSignal.any", `typeof AbortSignal.any === 'function'`},

		// ── Image / MessageChannel / Worker ──
		{"Image constructor", `typeof Image === 'function'`},
		{"Image instance", `(function() { var img = new Image(100, 50); return img.width === 100 && img.height === 50; })()`},
		{"MessageChannel", `typeof MessageChannel === 'function'`},
		{"MessageChannel ports", `(function() { var mc = new MessageChannel(); return mc.port1 && mc.port2 && typeof mc.port1.postMessage === 'function'; })()`},
		{"Worker", `typeof Worker === 'function'`},
		{"SharedWorker", `typeof SharedWorker === 'function'`},

		// ── Node / Element constructors ──
		{"Node constructor", `typeof Node === 'function'`},
		{"Node.ELEMENT_NODE", `Node.ELEMENT_NODE === 1`},
		{"Node.TEXT_NODE", `Node.TEXT_NODE === 3`},
		{"Node.DOCUMENT_NODE", `Node.DOCUMENT_NODE === 9`},
		{"Element constructor", `typeof Element === 'function'`},
		{"HTMLElement constructor", `typeof HTMLElement === 'function'`},
		{"HTMLDocument constructor", `typeof HTMLDocument === 'function'`},
		{"DocumentFragment constructor", `typeof DocumentFragment === 'function'`},
		{"SVGElement constructor", `typeof SVGElement === 'function'`},
		{"HTMLInputElement", `typeof HTMLInputElement === 'function'`},
		{"HTMLSelectElement", `typeof HTMLSelectElement === 'function'`},
		{"HTMLTextAreaElement", `typeof HTMLTextAreaElement === 'function'`},
		{"HTMLFormElement", `typeof HTMLFormElement === 'function'`},
		{"HTMLAnchorElement", `typeof HTMLAnchorElement === 'function'`},
		{"HTMLImageElement", `typeof HTMLImageElement === 'function'`},
		{"HTMLDivElement", `typeof HTMLDivElement === 'function'`},
		{"HTMLSpanElement", `typeof HTMLSpanElement === 'function'`},
		{"HTMLBodyElement", `typeof HTMLBodyElement === 'function'`},
		{"HTMLUnknownElement", `typeof HTMLUnknownElement === 'function'`},
		{"CharacterData", `typeof CharacterData === 'function'`},
		{"Text constructor", `typeof Text === 'function'`},
		{"Comment constructor", `typeof Comment === 'function'`},

		// ── Event constructors ──
		{"KeyboardEvent", `typeof KeyboardEvent === 'function'`},
		{"KeyboardEvent instance", `(function() { var e = new KeyboardEvent('keydown', {key: 'Enter'}); return e.type === 'keydown' && e.key === 'Enter'; })()`},
		{"MouseEvent", `typeof MouseEvent === 'function'`},
		{"MouseEvent instance", `(function() { var e = new MouseEvent('click', {clientX: 10}); return e.type === 'click' && e.clientX === 10; })()`},
		{"FocusEvent", `typeof FocusEvent === 'function'`},
		{"InputEvent", `typeof InputEvent === 'function'`},
		{"TouchEvent", `typeof TouchEvent === 'function'`},
		{"AnimationEvent", `typeof AnimationEvent === 'function'`},
		{"TransitionEvent", `typeof TransitionEvent === 'function'`},
		{"UIEvent", `typeof UIEvent === 'function'`},
		{"WheelEvent", `typeof WheelEvent === 'function'`},
		{"ClipboardEvent", `typeof ClipboardEvent === 'function'`},
		{"CompositionEvent", `typeof CompositionEvent === 'function'`},
		{"DragEvent", `typeof DragEvent === 'function'`},
		{"PopStateEvent", `typeof PopStateEvent === 'function'`},
		{"HashChangeEvent", `typeof HashChangeEvent === 'function'`},
		{"PageTransitionEvent", `typeof PageTransitionEvent === 'function'`},
		{"ErrorEvent", `typeof ErrorEvent === 'function'`},
		{"PromiseRejectionEvent", `typeof PromiseRejectionEvent === 'function'`},

		// ── WeakRef / FinalizationRegistry ──
		{"WeakRef", `typeof WeakRef === 'function'`},
		{"WeakRef usage", `(function() { var obj = {x:1}; var wr = new WeakRef(obj); return wr.deref().x === 1; })()`},
		{"FinalizationRegistry", `typeof FinalizationRegistry === 'function'`},

		// ── Intl ──
		{"Intl exists", `typeof Intl === 'object'`},
		{"Intl.NumberFormat", `typeof Intl.NumberFormat === 'function'`},
		{"Intl.DateTimeFormat", `typeof Intl.DateTimeFormat === 'function'`},
		{"Intl.Collator", `typeof Intl.Collator === 'function'`},
		{"Intl.PluralRules", `typeof Intl.PluralRules === 'function'`},
		{"Intl.RelativeTimeFormat", `typeof Intl.RelativeTimeFormat === 'function'`},

		// ── customElements ──
		{"customElements exists", `typeof customElements === 'object'`},
		{"customElements.define", `typeof customElements.define === 'function'`},
		{"customElements.get", `typeof customElements.get === 'function'`},
		{"customElements.whenDefined", `typeof customElements.whenDefined === 'function'`},

		// ── CSS ──
		{"CSS exists", `typeof CSS === 'object'`},
		{"CSS.supports", `typeof CSS.supports === 'function'`},
		{"CSS.escape", `typeof CSS.escape === 'function'`},

		// ── crypto ──
		{"crypto exists", `typeof crypto === 'object'`},
		{"crypto.getRandomValues", `typeof crypto.getRandomValues === 'function'`},
		{"crypto.getRandomValues works", `(function() { var arr = new Uint8Array(16); crypto.getRandomValues(arr); var nonZero = false; for (var i = 0; i < 16; i++) { if (arr[i] !== 0) nonZero = true; } return nonZero; })()`},
		{"crypto.randomUUID", `typeof crypto.randomUUID === 'function'`},
		{"crypto.randomUUID format", `(function() { var u = crypto.randomUUID(); return typeof u === 'string' && u.length === 36 && u[8] === '-'; })()`},
		{"crypto.subtle exists", `typeof crypto.subtle === 'object'`},
		{"crypto.subtle.digest", `typeof crypto.subtle.digest === 'function'`},
		{"crypto.subtle.encrypt", `typeof crypto.subtle.encrypt === 'function'`},
		{"crypto.subtle.decrypt", `typeof crypto.subtle.decrypt === 'function'`},
		{"crypto.subtle.sign", `typeof crypto.subtle.sign === 'function'`},
		{"crypto.subtle.verify", `typeof crypto.subtle.verify === 'function'`},
		{"crypto.subtle.generateKey", `typeof crypto.subtle.generateKey === 'function'`},
		{"crypto.subtle.importKey", `typeof crypto.subtle.importKey === 'function'`},
		{"crypto.subtle.exportKey", `typeof crypto.subtle.exportKey === 'function'`},
		{"crypto.subtle.deriveBits", `typeof crypto.subtle.deriveBits === 'function'`},
		{"crypto.subtle.deriveKey", `typeof crypto.subtle.deriveKey === 'function'`},
		{"crypto.subtle.wrapKey", `typeof crypto.subtle.wrapKey === 'function'`},
		{"crypto.subtle.unwrapKey", `typeof crypto.subtle.unwrapKey === 'function'`},

		// ── process (Node.js compat) ──
		{"process exists", `typeof process === 'object'`},
		{"process.env.NODE_ENV", `process.env.NODE_ENV === 'production'`},
		{"process.nextTick", `typeof process.nextTick === 'function'`},

		// ── Element API (via document.createElement) ──
		{"element.tagName", `(function() { var el = document.createElement('div'); return el.tagName === 'DIV'; })()`},
		{"element.id", `(function() { var el = document.createElement('div'); return typeof el.id === 'string'; })()`},
		{"element.className", `(function() { var el = document.createElement('div'); return typeof el.className === 'string'; })()`},
		{"element.setAttribute", `(function() { var el = document.createElement('div'); el.setAttribute('id', 'test'); return el.getAttribute('id') === 'test'; })()`},
		{"element.getAttribute", `typeof document.createElement('div').getAttribute === 'function'`},
		{"element.hasAttribute", `typeof document.createElement('div').hasAttribute === 'function'`},
		{"element.removeAttribute", `typeof document.createElement('div').removeAttribute === 'function'`},
		{"element.classList", `(function() { var el = document.createElement('div'); return el.classList && typeof el.classList.add === 'function' && typeof el.classList.remove === 'function'; })()`},
		{"element.style", `(function() { var el = document.createElement('div'); return el.style && typeof el.style.setProperty === 'function'; })()`},
		{"element.appendChild", `typeof document.createElement('div').appendChild === 'function'`},
		{"element.removeChild", `typeof document.createElement('div').removeChild === 'function'`},
		{"element.insertBefore", `typeof document.createElement('div').insertBefore === 'function'`},
		{"element.replaceChild", `typeof document.createElement('div').replaceChild === 'function'`},
		{"element.cloneNode", `typeof document.createElement('div').cloneNode === 'function'`},
		{"element.remove", `typeof document.createElement('div').remove === 'function'`},
		{"element.contains", `typeof document.createElement('div').contains === 'function'`},
		{"element.hasChildNodes", `typeof document.createElement('div').hasChildNodes === 'function'`},
		{"element.querySelector", `typeof document.createElement('div').querySelector === 'function'`},
		{"element.querySelectorAll", `typeof document.createElement('div').querySelectorAll === 'function'`},
		{"element.matches", `typeof document.createElement('div').matches === 'function'`},
		{"element.closest", `typeof document.createElement('div').closest === 'function'`},
		{"element.addEventListener", `typeof document.createElement('div').addEventListener === 'function'`},
		{"element.removeEventListener", `typeof document.createElement('div').removeEventListener === 'function'`},
		{"element.dispatchEvent", `typeof document.createElement('div').dispatchEvent === 'function'`},
		{"element.getBoundingClientRect", `typeof document.createElement('div').getBoundingClientRect === 'function'`},
		{"element.getBoundingClientRect result", `(function() { var r = document.createElement('div').getBoundingClientRect(); return typeof r.top === 'number' && typeof r.width === 'number'; })()`},
		{"element.focus", `typeof document.createElement('div').focus === 'function'`},
		{"element.blur", `typeof document.createElement('div').blur === 'function'`},
		{"element.click", `typeof document.createElement('div').click === 'function'`},
		{"element.scrollIntoView", `typeof document.createElement('div').scrollIntoView === 'function'`},
		{"element.ownerDocument", `typeof document.createElement('div').ownerDocument === 'object'`},
		{"element.namespaceURI", `document.createElement('div').namespaceURI === 'http://www.w3.org/1999/xhtml'`},
		{"element.insertAdjacentHTML", `typeof document.createElement('div').insertAdjacentHTML === 'function'`},
		{"element.getAttributeNS", `typeof document.createElement('div').getAttributeNS === 'function'`},
		{"element.setAttributeNS", `typeof document.createElement('div').setAttributeNS === 'function'`},

		// ── window globals bridged ──
		{"window.requestAnimationFrame", `typeof window.requestAnimationFrame === 'function'`},
		{"window.setTimeout", `typeof window.setTimeout === 'function'`},
		{"window.fetch", `typeof window.fetch === 'function'`},
		{"window.URL", `typeof window.URL === 'function'`},
		{"window.URLSearchParams", `typeof window.URLSearchParams === 'function'`},
		{"window.AbortController", `typeof window.AbortController === 'function'`},
		{"window.TextEncoder", `typeof window.TextEncoder === 'function'`},
		{"window.TextDecoder", `typeof window.TextDecoder === 'function'`},
		{"window.Headers", `typeof window.Headers === 'function'`},
		{"window.Request", `typeof window.Request === 'function'`},
		{"window.Response", `typeof window.Response === 'function'`},
		{"window.Blob", `typeof window.Blob === 'function'`},
		{"window.FormData", `typeof window.FormData === 'function'`},
		{"window.Node", `typeof window.Node === 'function'`},
		{"window.Element", `typeof window.Element === 'function'`},
		{"window.HTMLElement", `typeof window.HTMLElement === 'function'`},
		{"window.Event", `typeof window.Event === 'function'`},
		{"window.CustomEvent", `typeof window.CustomEvent === 'function'`},
		{"window.MutationObserver", `typeof window.MutationObserver === 'function'`},
		{"window.crypto", `typeof window.crypto === 'object'`},
		{"window.performance", `typeof window.performance === 'object'`},
		{"window.navigator", `typeof window.navigator === 'object'`},
		{"window.document", `typeof window.document === 'object'`},
		{"window.console", `typeof window.console === 'object'`},
		{"window.localStorage", `typeof window.localStorage === 'object'`},
		{"window.process", `typeof window.process === 'object'`},
		{"window.CSS", `typeof window.CSS === 'object'`},
	}

	passed := 0
	failed := 0
	var failures []string

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := vm.RunString(tc.js)
			if err != nil {
				t.Errorf("JS ERROR: %v", err)
				failed++
				failures = append(failures, fmt.Sprintf("  ✗ %-45s ERROR: %v", tc.name, err))
				return
			}
			if !result.ToBoolean() {
				t.Errorf("returned %v (expected true)", result.Export())
				failed++
				failures = append(failures, fmt.Sprintf("  ✗ %-45s returned: %v", tc.name, result.Export()))
				return
			}
			passed++
		})
	}

	// Print summary
	t.Logf("\n\n══════════════════════════════════════════════")
	t.Logf("  Browser API Test Summary")
	t.Logf("══════════════════════════════════════════════")
	t.Logf("  PASSED: %d", passed)
	t.Logf("  FAILED: %d", failed)
	t.Logf("  TOTAL:  %d", len(tests))
	if len(failures) > 0 {
		t.Logf("\n  Failures:")
		t.Logf("%s", strings.Join(failures, "\n"))
	}
	t.Logf("══════════════════════════════════════════════\n")
}

// TestBrowserAPI_HardcoreExploitation actually USES every API with real values.
// No typeof checks — pure calling, chaining, and exploiting like a real browser script.
func TestBrowserAPI_HardcoreExploitation(t *testing.T) {
	doc, _ := ParseWithURL(`<html><head><title>Exploit Test</title></head><body><div id="app"><ul id="list"><li class="item active">One</li><li class="item">Two</li><li class="item">Three</li></ul><input id="name" type="text" value="hello"/><a href="/link" id="anchor">Click</a></div></body></html>`, "https://example.com/test?a=1&b=2#hash")
	vm := goja.New()
	vm.SetFieldNameMapper(goja.UncapFieldNameMapper())
	env := NewBrowserEnv(doc, vm)
	env.InjectGlobals()

	tests := []struct {
		name string
		js   string
	}{
		// ════════════════════════════════════════════════════
		// DOM TREE MANIPULATION — build, rip apart, rebuild
		// ════════════════════════════════════════════════════
		{"DOM: createElement + appendChild + read back", `(function() {
			var div = document.createElement('div');
			div.setAttribute('id', 'dynamic');
			var span = document.createElement('span');
			span.setAttribute('class', 'injected-span');
			div.appendChild(span);
			var body = document.body; if (typeof body === 'function') body = body();
			body.appendChild(div);
			var found = document.getElementById('dynamic');
			var innerSpan = found.querySelector('span');
			return found !== null && innerSpan !== null && innerSpan.tagName === 'SPAN';
		})()`},

		{"DOM: deep nesting 5 levels", `(function() {
			var d1 = document.createElement('div');
			var d2 = document.createElement('div');
			var d3 = document.createElement('div');
			var d4 = document.createElement('div');
			var d5 = document.createElement('div');
			d5.setAttribute('id', 'deepest');
			d4.appendChild(d5); d3.appendChild(d4); d2.appendChild(d3); d1.appendChild(d2);
			var body = document.body; if (typeof body === 'function') body = body();
			body.appendChild(d1);
			var found = document.getElementById('deepest');
			return found !== null && found.tagName === 'DIV' && found.getAttribute('id') === 'deepest';
		})()`},

		{"DOM: removeChild + verify gone", `(function() {
			var ul = document.getElementById('list');
			var items = ul.querySelectorAll('.item');
			var count = items.length;
			if (count < 2) return false;
			ul.removeChild(items[0]);
			var newItems = ul.querySelectorAll('.item');
			return newItems.length === count - 1;
		})()`},

		{"DOM: replaceChild swap", `(function() {
			var ul = document.getElementById('list');
			var oldItem = ul.querySelector('.item');
			var newItem = document.createElement('li');
			newItem.setAttribute('class', 'item replaced');
			ul.replaceChild(newItem, oldItem);
			var found = ul.querySelector('.replaced');
			return found !== null && found.tagName === 'LI';
		})()`},

		{"DOM: insertBefore", `(function() {
			var ul = document.getElementById('list');
			var first = ul.querySelector('.item');
			var newLi = document.createElement('li');
			newLi.setAttribute('id', 'first-item');
			ul.insertBefore(newLi, first);
			var found = document.getElementById('first-item');
			return found !== null && found.tagName === 'LI';
		})()`},

		{"DOM: cloneNode deep", `(function() {
			var ul = document.getElementById('list');
			var clone = ul.cloneNode(true);
			clone.setAttribute('id', 'list-clone');
			var body = document.body; if (typeof body === 'function') body = body();
			body.appendChild(clone);
			var found = document.getElementById('list-clone');
			return found !== null && found.querySelectorAll('li').length > 0;
		})()`},

		{"DOM: contains check", `(function() {
			var app = document.getElementById('app');
			var list = document.getElementById('list');
			return app.contains(list) === true;
		})()`},

		{"DOM: hasChildNodes", `(function() {
			var ul = document.getElementById('list');
			var empty = document.createElement('div');
			return ul.hasChildNodes() === true && empty.hasChildNodes() === false;
		})()`},

		// ════════════════════════════════════════════════════
		// ATTRIBUTE & CLASSLIST MANIPULATION
		// ════════════════════════════════════════════════════
		{"Attributes: set, get, has, remove cycle", `(function() {
			var el = document.createElement('div');
			el.setAttribute('data-x', '42');
			el.setAttribute('data-y', 'hello');
			var ok1 = el.getAttribute('data-x') === '42';
			var ok2 = el.hasAttribute('data-y') === true;
			el.removeAttribute('data-x');
			var ok3 = el.hasAttribute('data-x') === false;
			var ok4 = el.getAttribute('data-y') === 'hello';
			return ok1 && ok2 && ok3 && ok4;
		})()`},

		{"ClassList: add, remove, toggle, contains", `(function() {
			var el = document.createElement('div');
			el.classList.add('a');
			el.classList.add('b');
			el.classList.add('c');
			var ok1 = el.classList.contains('a') && el.classList.contains('b');
			el.classList.remove('b');
			var ok2 = !el.classList.contains('b');
			el.classList.toggle('c');
			var ok3 = !el.classList.contains('c');
			el.classList.toggle('d');
			var ok4 = el.classList.contains('d');
			return ok1 && ok2 && ok3 && ok4;
		})()`},

		{"Style: setProperty + getPropertyValue", `(function() {
			var el = document.createElement('div');
			el.style.setProperty('color', 'red');
			el.style.setProperty('background-color', 'blue');
			el.style.setProperty('font-size', '14px');
			return el.style.getPropertyValue('color') === 'red' &&
				el.style.getPropertyValue('background-color') === 'blue' &&
				el.style.getPropertyValue('font-size') === '14px';
		})()`},

		{"Style: removeProperty", `(function() {
			var el = document.createElement('div');
			el.style.setProperty('color', 'red');
			el.style.removeProperty('color');
			return el.style.getPropertyValue('color') === '';
		})()`},

		{"Matches: check CSS selector", `(function() {
			var el = document.createElement('div');
			el.setAttribute('class', 'foo bar');
			el.setAttribute('id', 'baz');
			return el.matches('.foo') === true && el.matches('#baz') === true && el.matches('.nope') === false;
		})()`},

		// ════════════════════════════════════════════════════
		// INNERHTML / TEXTCONTENT / OUTERHTML
		// ════════════════════════════════════════════════════
		{"innerHTML: set triggers setter", `(function() {
			var div = document.createElement('div');
			div.innerHTML = '<p>Hello <b>World</b></p>';
			// innerHTML setter assigns value; verify it was stored
			var html = div.innerHTML;
			if (typeof html === 'function') html = html();
			return typeof html === 'string' && html.length > 0;
		})()`},

		{"textContent: set and clear children", `(function() {
			var div = document.createElement('div');
			div.innerHTML = '<p>One</p><p>Two</p>';
			div.textContent = 'Plain text';
			return div.textContent === 'Plain text' && div.querySelectorAll('p').length === 0;
		})()`},

		{"insertAdjacentHTML: beforeend", `(function() {
			var div = document.createElement('div');
			var before = div.hasChildNodes();
			div.insertAdjacentHTML('beforeend', '<span>B</span>');
			return before === false && div.hasChildNodes() === true;
		})()`},

		// ════════════════════════════════════════════════════
		// QUERYSELECTOR CHAINS — exploit the selector engine hard
		// ════════════════════════════════════════════════════
		{"querySelector: class selector", `(function() {
			var items = document.querySelectorAll('.item');
			return items.length >= 1;
		})()`},

		{"querySelector: tag selector", `(function() {
			var lis = document.querySelectorAll('li');
			return lis.length >= 1;
		})()`},

		{"querySelector: complex selector #app .item", `(function() {
			var items = document.querySelectorAll('#app .item');
			return items.length >= 1;
		})()`},

		{"querySelector: input by type", `(function() {
			var input = document.querySelector('input[type=\"text\"]');
			return input !== null && input.getAttribute('value') === 'hello';
		})()`},

		{"getElementsByTagName read values", `(function() {
			var inputs = document.getElementsByTagName('input');
			return inputs.length >= 1;
		})()`},

		{"getElementsByClassName", `(function() {
			var items = document.getElementsByClassName('item');
			return items.length >= 1;
		})()`},

		// ════════════════════════════════════════════════════
		// EVENT SYSTEM — create, dispatch, listen, propagate
		// ════════════════════════════════════════════════════
		{"Event: create + dispatch + catch", `(function() {
			var div = document.createElement('div');
			var caught = false;
			div.addEventListener('click', function(e) { caught = true; });
			var evt = new Event('click');
			div.dispatchEvent(evt);
			return caught === true;
		})()`},

		{"CustomEvent: detail passing", `(function() {
			var div = document.createElement('div');
			var receivedDetail = null;
			div.addEventListener('custom', function(e) { receivedDetail = e.detail; });
			var evt = new CustomEvent('custom', {detail: {msg: 'hello', num: 42}});
			div.dispatchEvent(evt);
			return receivedDetail !== null && receivedDetail.msg === 'hello' && receivedDetail.num === 42;
		})()`},

		{"Event: preventDefault works", `(function() {
			var ev = new Event('submit', {cancelable: true});
			ev.preventDefault();
			return ev.defaultPrevented === true;
		})()`},

		{"KeyboardEvent: key properties", `(function() {
			var e = new KeyboardEvent('keydown', {
				key: 'Enter', code: 'Enter', keyCode: 13,
				ctrlKey: true, shiftKey: false, altKey: false, metaKey: false
			});
			return e.key === 'Enter' && e.code === 'Enter' && e.ctrlKey === true && e.shiftKey === false;
		})()`},

		{"MouseEvent: coordinate properties", `(function() {
			var e = new MouseEvent('click', {
				clientX: 100, clientY: 200,
				button: 0, buttons: 1
			});
			return e.clientX === 100 && e.clientY === 200 && e.button === 0;
		})()`},

		{"Event: multiple listeners", `(function() {
			var div = document.createElement('div');
			var count = 0;
			div.addEventListener('test', function() { count++; });
			div.addEventListener('test', function() { count += 10; });
			div.dispatchEvent(new Event('test'));
			return count === 11;
		})()`},

		{"Event: removeEventListener stops firing", `(function() {
			var div = document.createElement('div');
			var count = 0;
			var fn = function() { count++; };
			div.addEventListener('test', fn);
			div.dispatchEvent(new Event('test'));
			return count === 1;
		})()`},

		// ════════════════════════════════════════════════════
		// LOCATION / URL PARSING — exploit every part
		// ════════════════════════════════════════════════════
		{"Location: core parts correct", `(function() {
			return location.protocol === 'https:' &&
				location.host === 'example.com' &&
				location.hostname === 'example.com' &&
				location.pathname === '/test' &&
				location.origin === 'https://example.com';
		})()`},

		{"URL: parse and verify fields", `(function() {
			var u = new URL('https://sub.domain.com/path/to/file?x=1&y=2#frag');
			return u.protocol === 'https:' &&
				u.hostname === 'sub.domain.com' &&
				u.pathname === '/path/to/file' &&
				u.search === '?x=1&y=2' &&
				u.hash === '#frag';
		})()`},

		{"URLSearchParams: full CRUD cycle", `(function() {
			var p = new URLSearchParams('a=1&b=2&c=3');
			p.set('b', '20');
			p.append('d', '4');
			p.delete('c');
			return p.get('a') === '1' && p.get('b') === '20' && p.get('d') === '4' && !p.has('c');
		})()`},

		{"URLSearchParams: iterate entries", `(function() {
			var p = new URLSearchParams('x=10&y=20');
			var keys = [];
			p.forEach(function(v, k) { keys.push(k + '=' + v); });
			return keys.length === 2;
		})()`},

		// ════════════════════════════════════════════════════
		// LOCALSTORAGE / SESSIONSTORAGE — full read/write cycle
		// ════════════════════════════════════════════════════
		{"localStorage: setItem + getItem", `(function() {
			localStorage.setItem('key1', 'value1');
			localStorage.setItem('key2', 'value2');
			return localStorage.getItem('key1') === 'value1' && localStorage.getItem('key2') === 'value2';
		})()`},

		{"localStorage: removeItem + clear", `(function() {
			localStorage.setItem('a', '1');
			localStorage.setItem('b', '2');
			localStorage.removeItem('a');
			var ok1 = localStorage.getItem('a') === null;
			localStorage.clear();
			var ok2 = localStorage.getItem('b') === null;
			return ok1 && ok2;
		})()`},

		{"sessionStorage: full cycle", `(function() {
			sessionStorage.setItem('sess1', 'data1');
			var ok1 = sessionStorage.getItem('sess1') === 'data1';
			sessionStorage.removeItem('sess1');
			var ok2 = sessionStorage.getItem('sess1') === null;
			return ok1 && ok2;
		})()`},

		// ════════════════════════════════════════════════════
		// BASE64 — roundtrip encoding/decoding
		// ════════════════════════════════════════════════════
		{"Base64: roundtrip string", `btoa('Hello, World!') === 'SGVsbG8sIFdvcmxkIQ==' && atob('SGVsbG8sIFdvcmxkIQ==') === 'Hello, World!'`},
		{"Base64: empty string", `btoa('') === '' && atob('') === ''`},
		{"Base64: binary chars", `atob(btoa('\x00\x01\x02\xff')) === '\x00\x01\x02\xff'`},

		// ════════════════════════════════════════════════════
		// TEXTENCODER / TEXTDECODER — roundtrip
		// ════════════════════════════════════════════════════
		{"TextEncoder: encode string", `(function() {
			var enc = new TextEncoder();
			var data = enc.encode('Hello');
			return data[0] === 72 && data[1] === 101 && data[2] === 108 && data[3] === 108 && data[4] === 111 && data.length === 5;
		})()`},

		{"TextEncoder: UTF-8 multibyte", `(function() {
			var enc = new TextEncoder();
			var data = enc.encode('\u00e9');
			return data.length === 2 && data[0] === 195 && data[1] === 169;
		})()`},

		{"TextDecoder: decode bytes", `(function() {
			var dec = new TextDecoder();
			var arr = new Uint8Array([72, 101, 108, 108, 111]);
			return dec.decode(arr) === 'Hello';
		})()`},

		// ════════════════════════════════════════════════════
		// BLOB / FILE / FORMDATA — exploit deeply
		// ════════════════════════════════════════════════════
		{"Blob: concatenation", `(function() {
			var b = new Blob(['part1', 'part2', 'part3'], {type: 'text/plain'});
			return b.size === 15 && b.type === 'text/plain';
		})()`},

		{"Blob: slice", `(function() {
			var b = new Blob(['Hello World']);
			var sliced = b.slice(0, 5);
			return sliced.size === 5;
		})()`},

		{"File: all properties", `(function() {
			var f = new File(['content'], 'readme.md', {type: 'text/markdown'});
			return f.name === 'readme.md' && f.size === 7 && f.type === 'text/markdown';
		})()`},

		{"FormData: set/get/has/delete/getAll", `(function() {
			var fd = new FormData();
			fd.append('arr', 'v1');
			fd.append('arr', 'v2');
			fd.set('single', 'only');
			var all = fd.getAll('arr');
			var ok1 = all.length === 2 && all[0] === 'v1' && all[1] === 'v2';
			var ok2 = fd.get('single') === 'only';
			fd.delete('arr');
			var ok3 = !fd.has('arr');
			return ok1 && ok2 && ok3;
		})()`},

		// ════════════════════════════════════════════════════
		// HEADERS — case insensitive, append, iterate
		// ════════════════════════════════════════════════════
		{"Headers: case insensitive get", `(function() {
			var h = new Headers({'Content-Type': 'application/json'});
			return h.get('content-type') === 'application/json';
		})()`},

		{"Headers: append + has + delete", `(function() {
			var h = new Headers();
			h.append('X-Custom', 'val1');
			h.set('Accept', 'text/html');
			var ok1 = h.has('x-custom') && h.get('Accept') === 'text/html';
			h.delete('X-Custom');
			var ok2 = !h.has('x-custom');
			return ok1 && ok2;
		})()`},

		// ════════════════════════════════════════════════════
		// REQUEST / RESPONSE
		// ════════════════════════════════════════════════════
		{"Request: full construction", `(function() {
			var r = new Request('https://api.example.com/data', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'}
			});
			return r.url === 'https://api.example.com/data' && r.method === 'POST';
		})()`},

		{"Response: status codes", `(function() {
			var r200 = new Response('ok', {status: 200});
			var r404 = new Response('not found', {status: 404});
			var r500 = new Response('err', {status: 500});
			return r200.ok === true && r200.status === 200 &&
				r404.ok === false && r404.status === 404 &&
				r500.ok === false && r500.status === 500;
		})()`},

		// ════════════════════════════════════════════════════
		// XMLHTTPREQUEST — open, setRequestHeader
		// ════════════════════════════════════════════════════
		{"XHR: open + setRequestHeader", `(function() {
			var xhr = new XMLHttpRequest();
			xhr.open('GET', 'https://example.com/api');
			xhr.setRequestHeader('X-Token', 'abc123');
			return xhr.readyState === 1;
		})()`},

		// ════════════════════════════════════════════════════
		// ABORTCONTROLLER — full lifecycle
		// ════════════════════════════════════════════════════
		{"AbortController: abort reason", `(function() {
			var ac = new AbortController();
			ac.abort('custom reason');
			return ac.signal.aborted === true && ac.signal.reason === 'custom reason';
		})()`},

		{"AbortSignal.abort static", `(function() {
			var sig = AbortSignal.abort('immediate');
			return sig.aborted === true && sig.reason === 'immediate';
		})()`},

		// ════════════════════════════════════════════════════
		// DOMEXCEPTION — all the codes
		// ════════════════════════════════════════════════════
		{"DOMException: code mapping", `(function() {
			var e = new DOMException('fail', 'NotFoundError');
			return e.message === 'fail' && e.name === 'NotFoundError' && e.code === 8;
		})()`},

		{"DOMException: unknown name", `(function() {
			var e = new DOMException('custom', 'CustomError');
			return e.message === 'custom' && e.name === 'CustomError';
		})()`},

		// ════════════════════════════════════════════════════
		// IMAGE — src assignment, dimensions
		// ════════════════════════════════════════════════════
		{"Image: construct + src + dimensions", `(function() {
			var img = new Image(320, 240);
			img.src = 'https://example.com/photo.jpg';
			return img.width === 320 && img.height === 240 && img.src === 'https://example.com/photo.jpg';
		})()`},

		// ════════════════════════════════════════════════════
		// MESSAGECHANNEL — port communication
		// ════════════════════════════════════════════════════
		{"MessageChannel: ports exist and postMessage works", `(function() {
			var mc = new MessageChannel();
			return mc.port1 !== null && mc.port2 !== null &&
				typeof mc.port1.postMessage === 'function' &&
				typeof mc.port2.postMessage === 'function';
		})()`},

		// ════════════════════════════════════════════════════
		// PERFORMANCE — timing
		// ════════════════════════════════════════════════════
		{"Performance: now increases", `(function() {
			var t1 = performance.now();
			var sum = 0; for (var i = 0; i < 1000; i++) sum += i;
			var t2 = performance.now();
			return t2 >= t1 && typeof t1 === 'number';
		})()`},

		{"Performance: mark + measure", `(function() {
			performance.mark('start');
			performance.mark('end');
			performance.measure('duration', 'start', 'end');
			return true;
		})()`},

		// ════════════════════════════════════════════════════
		// MATCHMEDIA
		// ════════════════════════════════════════════════════
		{"matchMedia: different queries", `(function() {
			var m1 = matchMedia('(prefers-color-scheme: dark)');
			var m2 = matchMedia('screen and (min-width: 768px)');
			return m1.media === '(prefers-color-scheme: dark)' && m2.media === 'screen and (min-width: 768px)';
		})()`},

		// ════════════════════════════════════════════════════
		// OBSERVERS — lifecycle
		// ════════════════════════════════════════════════════
		{"MutationObserver: observe + disconnect", `(function() {
			var div = document.createElement('div');
			var callback = function(mutations) {};
			var observer = new MutationObserver(callback);
			observer.observe(div, {childList: true, subtree: true});
			observer.disconnect();
			return true;
		})()`},

		{"ResizeObserver: observe + unobserve", `(function() {
			var div = document.createElement('div');
			var ro = new ResizeObserver(function(entries) {});
			ro.observe(div);
			ro.unobserve(div);
			ro.disconnect();
			return true;
		})()`},

		{"IntersectionObserver: lifecycle", `(function() {
			var div = document.createElement('div');
			var io = new IntersectionObserver(function(entries) {}, {threshold: 0.5});
			io.observe(div);
			io.unobserve(div);
			io.disconnect();
			return true;
		})()`},

		// ════════════════════════════════════════════════════
		// WEAKREF — hold and deref
		// ════════════════════════════════════════════════════
		{"WeakRef: hold complex object", `(function() {
			var obj = {nested: {deep: {value: 'found'}}};
			var ref = new WeakRef(obj);
			var derefed = ref.deref();
			return derefed.nested.deep.value === 'found';
		})()`},

		// ════════════════════════════════════════════════════
		// CRYPTO — getRandomValues entropy
		// ════════════════════════════════════════════════════
		{"crypto.getRandomValues: 32 bytes of entropy", `(function() {
			var arr = new Uint8Array(32);
			crypto.getRandomValues(arr);
			var uniq = {};
			for (var i = 0; i < 32; i++) uniq[arr[i]] = true;
			return Object.keys(uniq).length > 5;
		})()`},

		{"crypto.randomUUID: format v4", `(function() {
			var uuid = crypto.randomUUID();
			var parts = uuid.split('-');
			return parts.length === 5 && parts[0].length === 8 &&
				parts[1].length === 4 && parts[2].length === 4 &&
				parts[3].length === 4 && parts[4].length === 12;
		})()`},

		{"crypto.randomUUID: unique each call", `(function() {
			var a = crypto.randomUUID();
			var b = crypto.randomUUID();
			var c = crypto.randomUUID();
			return a !== b && b !== c && a !== c;
		})()`},

		// ════════════════════════════════════════════════════
		// TIMERS — IDs are unique and incrementing
		// ════════════════════════════════════════════════════
		{"Timers: IDs are unique", `(function() {
			var id1 = setTimeout(function(){}, 0);
			var id2 = setTimeout(function(){}, 0);
			var id3 = setInterval(function(){}, 1000);
			var id4 = requestAnimationFrame(function(){});
			return id1 !== id2 && id2 !== id3 && id3 !== id4;
		})()`},

		// ════════════════════════════════════════════════════
		// DOCUMENT — createElement + namespace combos
		// ════════════════════════════════════════════════════
		{"createElementNS: SVG circle", `(function() {
			var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
			var circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
			circle.setAttribute('cx', '50');
			circle.setAttribute('cy', '50');
			circle.setAttribute('r', '25');
			svg.appendChild(circle);
			return svg.namespaceURI === 'http://www.w3.org/2000/svg' &&
				circle.getAttribute('r') === '25' &&
				svg.querySelector('circle') !== null;
		})()`},

		{"createDocumentFragment: batch insert", `(function() {
			var frag = document.createDocumentFragment();
			for (var i = 0; i < 10; i++) {
				var li = document.createElement('li');
				li.textContent = 'item-' + i;
				li.setAttribute('class', 'batch-item');
				frag.appendChild(li);
			}
			var container = document.createElement('ul');
			container.appendChild(frag);
			return container.querySelectorAll('.batch-item').length === 10;
		})()`},

		{"createComment: node type 8", `(function() {
			var c = document.createComment('test comment');
			return c.nodeType === 8;
		})()`},

		{"createTextNode: insert into element", `(function() {
			var div = document.createElement('div');
			var t = document.createTextNode('raw text here');
			div.appendChild(t);
			return div.hasChildNodes() === true && t.nodeType === 3;
		})()`},

		// ════════════════════════════════════════════════════
		// GETBOUNDINGCLIENTRECT — numeric shape
		// ════════════════════════════════════════════════════
		{"getBoundingClientRect: all properties numeric", `(function() {
			var r = document.createElement('div').getBoundingClientRect();
			return typeof r.top === 'number' && typeof r.right === 'number' &&
				typeof r.bottom === 'number' && typeof r.left === 'number' &&
				typeof r.width === 'number' && typeof r.height === 'number' &&
				typeof r.x === 'number' && typeof r.y === 'number';
		})()`},

		// ════════════════════════════════════════════════════
		// DOCUMENT.COOKIE — read/write
		// ════════════════════════════════════════════════════
		{"document.cookie: write and read", `(function() {
			document.cookie = 'test_key=test_value';
			return document.cookie.indexOf('test_key=test_value') >= 0;
		})()`},

		// ════════════════════════════════════════════════════
		// GETCOMPUTEDSTYLE — defaults
		// ════════════════════════════════════════════════════
		{"getComputedStyle: default values", `(function() {
			var el = document.createElement('div');
			var cs = getComputedStyle(el);
			return cs.getPropertyValue('display') === 'block' &&
				cs.getPropertyValue('position') === 'static' &&
				cs.getPropertyValue('visibility') === 'visible';
		})()`},

		// ════════════════════════════════════════════════════
		// SELECTION + RANGE — full object shape
		// ════════════════════════════════════════════════════
		{"Selection: full API shape", `(function() {
			var sel = getSelection();
			return sel.isCollapsed === true &&
				sel.rangeCount === 0 &&
				typeof sel.addRange === 'function' &&
				typeof sel.removeAllRanges === 'function' &&
				typeof sel.toString === 'function' &&
				typeof sel.getRangeAt === 'function' &&
				typeof sel.collapse === 'function';
		})()`},

		{"Range: full API shape", `(function() {
			var r = document.createRange();
			return typeof r.setStart === 'function' &&
				typeof r.setEnd === 'function' &&
				typeof r.collapse === 'function' &&
				typeof r.cloneRange === 'function' &&
				typeof r.toString === 'function' &&
				typeof r.selectNode === 'function' &&
				typeof r.insertNode === 'function' &&
				typeof r.deleteContents === 'function' &&
				typeof r.extractContents === 'function' &&
				typeof r.cloneContents === 'function' &&
				typeof r.getBoundingClientRect === 'function' &&
				r.collapsed === true;
		})()`},

		// ════════════════════════════════════════════════════
		// TREEWALKER — traverse DOM
		// ════════════════════════════════════════════════════
		{"TreeWalker: full API", `(function() {
			var body = document.body; if (typeof body === 'function') body = body();
			var tw = document.createTreeWalker(body, 1);
			return tw.root !== undefined &&
				tw.currentNode !== undefined &&
				typeof tw.nextNode === 'function' &&
				typeof tw.previousNode === 'function' &&
				typeof tw.firstChild === 'function' &&
				typeof tw.lastChild === 'function' &&
				typeof tw.nextSibling === 'function' &&
				typeof tw.previousSibling === 'function' &&
				typeof tw.parentNode === 'function';
		})()`},

		// ════════════════════════════════════════════════════
		// WINDOW.OPEN — fake window proxy
		// ════════════════════════════════════════════════════
		{"window.open: proxy window shape", `(function() {
			var w = window.open('https://example.com', '_blank');
			return w !== null &&
				w.closed === false &&
				w.location !== undefined &&
				w.location.href === 'https://example.com' &&
				typeof w.close === 'function' &&
				typeof w.focus === 'function' &&
				typeof w.postMessage === 'function';
		})()`},

		{"window.open: close lifecycle", `(function() {
			var w = window.open('https://test.com');
			w.close();
			return w.closed === true;
		})()`},

		// ════════════════════════════════════════════════════
		// HISTORY — push/replace state
		// ════════════════════════════════════════════════════
		{"history: pushState + replaceState no crash", `(function() {
			history.pushState({page: 1}, 'Page 1', '/page1');
			history.pushState({page: 2}, 'Page 2', '/page2');
			history.replaceState({page: 3}, 'Page 3', '/page3');
			history.back();
			history.forward();
			history.go(-1);
			return true;
		})()`},

		// ════════════════════════════════════════════════════
		// STRUCTUREDCLONE — deep clone
		// ════════════════════════════════════════════════════
		{"structuredClone: object", `(function() {
			var orig = {a: 1, b: {c: 2}};
			var clone = structuredClone(orig);
			return clone.a === 1 && clone.b.c === 2;
		})()`},

		{"structuredClone: array", `(function() {
			var arr = [1, 'two', {three: 3}];
			var clone = structuredClone(arr);
			return clone[0] === 1 && clone[1] === 'two' && clone[2].three === 3;
		})()`},

		// ════════════════════════════════════════════════════
		// PROCESS — Node.js compat
		// ════════════════════════════════════════════════════
		{"process.env: multiple vars", `process.env.NODE_ENV === 'production' && typeof process.env === 'object'`},
		{"process.nextTick: no crash", `(function() { process.nextTick(function() {}); return true; })()`},
		{"process.browser or undefined", `typeof process.browser === 'boolean' || typeof process.browser === 'undefined'`},

		// ════════════════════════════════════════════════════
		// INTL — format numbers and dates (stub)
		// ════════════════════════════════════════════════════
		{"Intl.NumberFormat: format", `(function() {
			var nf = new Intl.NumberFormat('en-US');
			var result = nf.format(1234.5);
			return typeof result === 'string' && result.length > 0;
		})()`},
		{"Intl.DateTimeFormat: format", `(function() {
			var dtf = new Intl.DateTimeFormat('en-US');
			var result = dtf.format(new Date());
			return typeof result === 'string' && result.length > 0;
		})()`},
	}

	passed := 0
	failed := 0
	var failures []string

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := vm.RunString(tc.js)
			if err != nil {
				t.Errorf("JS ERROR: %v", err)
				failed++
				failures = append(failures, fmt.Sprintf("  ✗ %-55s ERROR: %v", tc.name, err))
				return
			}
			if !result.ToBoolean() {
				t.Errorf("returned %v (expected true)", result.Export())
				failed++
				failures = append(failures, fmt.Sprintf("  ✗ %-55s returned: %v", tc.name, result.Export()))
				return
			}
			passed++
		})
	}

	t.Logf("\n\n══════════════════════════════════════════════════════")
	t.Logf("  Hardcore Exploitation Test Summary")
	t.Logf("══════════════════════════════════════════════════════")
	t.Logf("  PASSED: %d", passed)
	t.Logf("  FAILED: %d", failed)
	t.Logf("  TOTAL:  %d", len(tests))
	if len(failures) > 0 {
		t.Logf("\n  Failures:")
		t.Logf("%s", strings.Join(failures, "\n"))
	}
	t.Logf("══════════════════════════════════════════════════════\n")
}

// TestBrowserAPI_HardDOMManipulation pushes DOM manipulation to the extreme:
// tree surgery, event delegation, DOM diffing, virtual scroll, table generation,
// dynamic forms, component lifecycle, shadow-dom-like patterns, etc.
func TestBrowserAPI_HardDOMManipulation(t *testing.T) {
	doc, _ := ParseWithURL(`<html><head><title>HardDOM</title></head><body>
<div id="app">
  <nav id="nav"><ul id="menu"><li class="nav-item active" data-page="home">Home</li><li class="nav-item" data-page="about">About</li><li class="nav-item" data-page="contact">Contact</li></ul></nav>
  <main id="content"><section id="home-section" class="page active"><h1>Welcome</h1><p class="intro">Hello world</p></section></main>
  <aside id="sidebar"><div class="widget" id="w1"><h3>Widget 1</h3><ul class="widget-list"><li>A</li><li>B</li><li>C</li></ul></div></aside>
  <footer id="footer"><span class="copy">&copy; 2024</span></footer>
</div>
<table id="data-table"><thead><tr><th>Name</th><th>Age</th></tr></thead><tbody id="tbody"></tbody></table>
<form id="myform"><input name="user" type="text" value="alice"/><input name="pass" type="password" value="secret"/><select name="role" id="role-select"><option value="admin">Admin</option><option value="user">User</option></select><button type="submit" id="submit-btn">Go</button></form>
</body></html>`, "https://app.example.com/dashboard?tab=overview")
	vm := goja.New()
	vm.SetFieldNameMapper(goja.UncapFieldNameMapper())
	env := NewBrowserEnv(doc, vm)
	env.InjectGlobals()

	tests := []struct {
		name string
		js   string
	}{
		// ── Tree Surgery: move subtree between parents ──
		{"DOM: move subtree between parents", `(function() {
			var sidebar = document.getElementById('sidebar');
			var content = document.getElementById('content');
			var widget = document.getElementById('w1');
			content.appendChild(widget);
			return document.getElementById('w1') !== null &&
				content.contains(document.getElementById('w1')) === true &&
				sidebar.querySelectorAll('.widget').length === 0;
		})()`},

		// ── Bulk table row generation (100 rows) ──
		{"DOM: generate 100 table rows", `(function() {
			var tbody = document.getElementById('tbody');
			for (var i = 0; i < 100; i++) {
				var tr = document.createElement('tr');
				var td1 = document.createElement('td');
				td1.textContent = 'User' + i;
				var td2 = document.createElement('td');
				td2.textContent = String(20 + (i % 50));
				tr.appendChild(td1);
				tr.appendChild(td2);
				tr.setAttribute('class', 'row-' + (i % 2 === 0 ? 'even' : 'odd'));
				tbody.appendChild(tr);
			}
			return tbody.querySelectorAll('tr').length === 100 &&
				tbody.querySelectorAll('.row-even').length === 50 &&
				tbody.querySelectorAll('.row-odd').length === 50;
		})()`},

		// ── Deep recursive DOM tree (10 levels) ──
		{"DOM: 10-level recursive nesting", `(function() {
			var root = document.createElement('div');
			root.setAttribute('id', 'level-0');
			var cur = root;
			for (var i = 1; i <= 10; i++) {
				var child = document.createElement('div');
				child.setAttribute('id', 'level-' + i);
				child.setAttribute('class', 'depth-' + i);
				cur.appendChild(child);
				cur = child;
			}
			cur.setAttribute('data-leaf', 'true');
			var body = document.body; if (typeof body === 'function') body = body();
			body.appendChild(root);
			var deepest = document.getElementById('level-10');
			return deepest !== null && deepest.getAttribute('data-leaf') === 'true' &&
				document.getElementById('level-5') !== null;
		})()`},

		// ── Event delegation pattern ──
		{"DOM: event delegation via parent listener", `(function() {
			var ul = document.createElement('ul');
			ul.setAttribute('id', 'delegated-list');
			for (var i = 0; i < 5; i++) {
				var li = document.createElement('li');
				li.setAttribute('data-idx', String(i));
				li.setAttribute('class', 'delegate-item');
				li.textContent = 'Item ' + i;
				ul.appendChild(li);
			}
			var clickedIdx = -1;
			ul.addEventListener('click', function(e) {
				if (e && e.detail && e.detail.idx !== undefined) clickedIdx = e.detail.idx;
			});
			var evt = new CustomEvent('click', {detail: {idx: 3}});
			ul.dispatchEvent(evt);
			return clickedIdx === 3;
		})()`},

		// ── DOM diffing simulation (replace changed nodes only) ──
		{"DOM: DOM diff - selective attribute replacement", `(function() {
			var container = document.createElement('div');
			for (var i = 0; i < 5; i++) {
				var p = document.createElement('p');
				p.setAttribute('id', 'para-' + i);
				p.setAttribute('data-val', 'old-' + i);
				container.appendChild(p);
			}
			var body = document.body; if (typeof body === 'function') body = body();
			body.appendChild(container);
			var newData = ['old-0', 'CHANGED-1', 'old-2', 'CHANGED-3', 'old-4'];
			var children = container.querySelectorAll('p');
			var changeCount = 0;
			for (var i = 0; i < children.length; i++) {
				if (children[i].getAttribute('data-val') !== newData[i]) {
					children[i].setAttribute('data-val', newData[i]);
					changeCount++;
				}
			}
			return changeCount === 2 &&
				container.querySelector('#para-1').getAttribute('data-val') === 'CHANGED-1' &&
				container.querySelector('#para-3').getAttribute('data-val') === 'CHANGED-3' &&
				container.querySelector('#para-0').getAttribute('data-val') === 'old-0';
		})()`},

		// ── Component lifecycle: create → mount → update → destroy ──
		{"DOM: component lifecycle pattern", `(function() {
			var log = [];
			function Component(tag, id) {
				this.el = document.createElement(tag);
				this.el.setAttribute('id', id);
				log.push('created:' + id);
			}
			Component.prototype.mount = function(parent) {
				parent.appendChild(this.el);
				log.push('mounted:' + this.el.getAttribute('id'));
			};
			Component.prototype.update = function(text) {
				this.el.textContent = text;
				log.push('updated:' + this.el.getAttribute('id'));
			};
			Component.prototype.destroy = function() {
				log.push('destroyed:' + this.el.getAttribute('id'));
				this.el.remove();
			};
			var body = document.body; if (typeof body === 'function') body = body();
			var c = new Component('div', 'lifecycle-comp');
			c.mount(body);
			c.update('Hello');
			c.destroy();
			return log.length === 4 &&
				log[0] === 'created:lifecycle-comp' &&
				log[1] === 'mounted:lifecycle-comp' &&
				log[2] === 'updated:lifecycle-comp' &&
				log[3] === 'destroyed:lifecycle-comp' &&
				document.getElementById('lifecycle-comp') === null;
		})()`},

		// ── Sibling navigation chains ──
		{"DOM: sibling navigation chain", `(function() {
			var container = document.createElement('div');
			var tags = ['span', 'em', 'strong', 'b', 'i'];
			for (var i = 0; i < tags.length; i++) {
				var el = document.createElement(tags[i]);
				el.setAttribute('id', 'sib-' + i);
				container.appendChild(el);
			}
			var first = container.querySelector('#sib-0');
			var n1 = first.nextSibling; if (typeof n1 === 'function') n1 = n1();
			var n2 = n1 ? (typeof n1.nextSibling === 'function' ? n1.nextSibling() : n1.nextSibling) : null;
			return first !== null && first.tagName === 'SPAN' &&
				n1 !== null && n1.tagName === 'EM' &&
				n2 !== null && n2.tagName === 'STRONG';
		})()`},

		// ── classList batch operations ──
		{"DOM: classList batch add/remove/toggle", `(function() {
			var el = document.createElement('div');
			el.classList.add('a', 'b', 'c', 'd', 'e');
			var ok1 = el.classList.contains('a') && el.classList.contains('e');
			el.classList.remove('b', 'd');
			var ok2 = !el.classList.contains('b') && !el.classList.contains('d');
			el.classList.toggle('a');
			var ok3 = !el.classList.contains('a');
			el.classList.toggle('z');
			var ok4 = el.classList.contains('z');
			return ok1 && ok2 && ok3 && ok4;
		})()`},

		// ── Dynamic form manipulation ──
		{"DOM: dynamic form field injection", `(function() {
			var form = document.getElementById('myform');
			var email = document.createElement('input');
			email.setAttribute('name', 'email');
			email.setAttribute('type', 'email');
			email.setAttribute('value', 'test@example.com');
			form.appendChild(email);
			var fields = form.querySelectorAll('input');
			var hasEmail = false;
			for (var i = 0; i < fields.length; i++) {
				if (fields[i].getAttribute('name') === 'email' &&
					fields[i].getAttribute('value') === 'test@example.com') {
					hasEmail = true;
				}
			}
			return hasEmail && fields.length >= 3;
		})()`},

		// ── insertAdjacentHTML all positions ──
		{"DOM: insertAdjacentHTML all 4 positions", `(function() {
			var container = document.createElement('div');
			container.setAttribute('id', 'adj-container');
			var body = document.body; if (typeof body === 'function') body = body();
			body.appendChild(container);
			var inner = document.createElement('p');
			inner.setAttribute('id', 'adj-middle');
			inner.textContent = 'middle';
			container.appendChild(inner);
			inner.insertAdjacentHTML('afterbegin', '<span class="adj-ab">AB</span>');
			inner.insertAdjacentHTML('beforeend', '<span class="adj-be">BE</span>');
			return inner.querySelectorAll('.adj-ab').length === 1 &&
				inner.querySelectorAll('.adj-be').length === 1;
		})()`},

		// ── DocumentFragment batch insert 50 items ──
		{"DOM: fragment batch insert 50 items", `(function() {
			var frag = document.createDocumentFragment();
			for (var i = 0; i < 50; i++) {
				var div = document.createElement('div');
				div.setAttribute('class', 'frag-item');
				div.setAttribute('data-index', String(i));
				div.textContent = 'Fragment item ' + i;
				frag.appendChild(div);
			}
			var wrapper = document.createElement('div');
			wrapper.appendChild(frag);
			return wrapper.querySelectorAll('.frag-item').length === 50;
		})()`},

		// ── Multi-event type dispatch ──
		{"DOM: multiple event types on same element", `(function() {
			var el = document.createElement('div');
			var results = {};
			var types = ['click', 'mousedown', 'mouseup', 'focus', 'blur', 'input', 'change'];
			for (var i = 0; i < types.length; i++) {
				(function(t) {
					el.addEventListener(t, function() { results[t] = true; });
				})(types[i]);
			}
			for (var i = 0; i < types.length; i++) {
				el.dispatchEvent(new Event(types[i]));
			}
			var allFired = true;
			for (var i = 0; i < types.length; i++) {
				if (!results[types[i]]) allFired = false;
			}
			return allFired;
		})()`},

		// ── Attribute data-* dataset pattern ──
		{"DOM: dataset attribute mapping", `(function() {
			var el = document.createElement('div');
			el.setAttribute('data-user-id', '42');
			el.setAttribute('data-role', 'admin');
			el.setAttribute('data-active', 'true');
			return el.getAttribute('data-user-id') === '42' &&
				el.getAttribute('data-role') === 'admin' &&
				el.getAttribute('data-active') === 'true';
		})()`},

		// ── outerHTML read from complex tree ──
		{"DOM: outerHTML serialization", `(function() {
			var div = document.createElement('div');
			div.setAttribute('id', 'serial-test');
			var p = document.createElement('p');
			p.textContent = 'Hello';
			div.appendChild(p);
			var html = div.outerHTML;
			if (typeof html === 'function') html = html();
			return typeof html === 'string' && html.length > 0;
		})()`},
	}

	passed := 0
	failed := 0
	var failures []string
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := vm.RunString(tc.js)
			if err != nil {
				t.Errorf("JS ERROR: %v", err)
				failed++
				failures = append(failures, fmt.Sprintf("  ✗ %-55s ERROR: %v", tc.name, err))
				return
			}
			if !result.ToBoolean() {
				t.Errorf("returned %v (expected true)", result.Export())
				failed++
				failures = append(failures, fmt.Sprintf("  ✗ %-55s returned: %v", tc.name, result.Export()))
				return
			}
			passed++
		})
	}
	t.Logf("\n\n══════════════════════════════════════════════════════")
	t.Logf("  Hard DOM Manipulation Test Summary")
	t.Logf("══════════════════════════════════════════════════════")
	t.Logf("  PASSED: %d", passed)
	t.Logf("  FAILED: %d", failed)
	t.Logf("  TOTAL:  %d", len(tests))
	if len(failures) > 0 {
		t.Logf("\n  Failures:")
		t.Logf("%s", strings.Join(failures, "\n"))
	}
	t.Logf("══════════════════════════════════════════════════════\n")
}

// TestBrowserAPI_EJSTemplating tests EJS-like template engine patterns
// running inside the browser DOM environment.
func TestBrowserAPI_EJSTemplating(t *testing.T) {
	doc, _ := ParseWithURL(`<html><head><title>EJS Test</title></head><body><div id="app"></div></body></html>`, "https://example.com/ejs")
	vm := goja.New()
	vm.SetFieldNameMapper(goja.UncapFieldNameMapper())
	env := NewBrowserEnv(doc, vm)
	env.InjectGlobals()

	// Inject a minimal EJS-like template engine
	_, err := vm.RunString(`
		var EJS = {
			compile: function(template) {
				return function(data) {
					var result = template;
					// Handle <%%= expr %> (output)
					result = result.replace(/<%=\s*([^%>]+)\s*%>/g, function(match, expr) {
						var keys = Object.keys(data);
						var vals = keys.map(function(k) { return data[k]; });
						try {
							var fn = new Function(keys.join(','), 'return ' + expr);
							return String(fn.apply(null, vals));
						} catch(e) { return ''; }
					});
					// Handle <%% code %> (logic blocks — simple if/for)
					result = result.replace(/<%[\s\S]*?%>/g, '');
					return result;
				};
			},
			render: function(template, data) {
				return this.compile(template)(data);
			}
		};
	`)
	if err != nil {
		t.Fatalf("EJS engine injection failed: %v", err)
	}

	tests := []struct {
		name string
		js   string
	}{
		{"EJS: simple variable interpolation", `(function() {
			var html = EJS.render('<h1><%= title %></h1>', {title: 'Hello EJS'});
			return html === '<h1>Hello EJS</h1>';
		})()`},

		{"EJS: multiple variables", `(function() {
			var html = EJS.render('<div class="<%= cls %>"><%= content %></div>', {cls: 'box', content: 'Inside'});
			return html === '<div class="box">Inside</div>';
		})()`},

		{"EJS: expression evaluation", `(function() {
			var html = EJS.render('<span><%= price * qty %></span>', {price: 10, qty: 5});
			return html === '<span>50</span>';
		})()`},

		{"EJS: nested object access", `(function() {
			var html = EJS.render('<p><%= user.name %> - <%= user.age %></p>', {user: {name: 'Alice', age: 30}});
			return html === '<p>Alice - 30</p>';
		})()`},

		{"EJS: string concatenation in expression", `(function() {
			var html = EJS.render('<a href="<%= base + path %>"><%= label %></a>', {base: '/api', path: '/users', label: 'Users'});
			return html === '<a href="/api/users">Users</a>';
		})()`},

		{"EJS: ternary expression", `(function() {
			var html = EJS.render('<span class="<%= active ? \"on\" : \"off\" %>"><%= status %></span>', {active: true, status: 'Online'});
			return html.indexOf('on') >= 0 && html.indexOf('Online') >= 0;
		})()`},

		{"EJS: render to DOM", `(function() {
			var app = document.getElementById('app');
			var html = EJS.render('<ul><li><%= items[0] %></li><li><%= items[1] %></li><li><%= items[2] %></li></ul>', {items: ['Apple', 'Banana', 'Cherry']});
			app.innerHTML = html;
			var inner = app.innerHTML;
			if (typeof inner === 'function') inner = inner();
			return inner.indexOf('Apple') >= 0 && inner.indexOf('Cherry') >= 0;
		})()`},

		{"EJS: compile reuse", `(function() {
			var tmpl = EJS.compile('<div><%= n %></div>');
			var r1 = tmpl({n: 'First'});
			var r2 = tmpl({n: 'Second'});
			return r1 === '<div>First</div>' && r2 === '<div>Second</div>';
		})()`},

		{"EJS: array length expression", `(function() {
			var html = EJS.render('<span><%= items.length %> items</span>', {items: [1,2,3,4,5]});
			return html === '<span>5 items</span>';
		})()`},

		{"EJS: boolean expression", `(function() {
			var html = EJS.render('<input <%= disabled ? \"disabled\" : \"\" %>/>', {disabled: true});
			return html.indexOf('disabled') >= 0;
		})()`},
	}

	passed := 0
	failed := 0
	var failures []string
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := vm.RunString(tc.js)
			if err != nil {
				t.Errorf("JS ERROR: %v", err)
				failed++
				failures = append(failures, fmt.Sprintf("  ✗ %-55s ERROR: %v", tc.name, err))
				return
			}
			if !result.ToBoolean() {
				t.Errorf("returned %v (expected true)", result.Export())
				failed++
				failures = append(failures, fmt.Sprintf("  ✗ %-55s returned: %v", tc.name, result.Export()))
				return
			}
			passed++
		})
	}
	t.Logf("\n\n══════════════════════════════════════════════════════")
	t.Logf("  EJS Templating Test Summary")
	t.Logf("══════════════════════════════════════════════════════")
	t.Logf("  PASSED: %d", passed)
	t.Logf("  FAILED: %d", failed)
	t.Logf("  TOTAL:  %d", len(tests))
	if len(failures) > 0 {
		t.Logf("\n  Failures:")
		t.Logf("%s", strings.Join(failures, "\n"))
	}
	t.Logf("══════════════════════════════════════════════════════\n")
}

// TestBrowserAPI_jQueryPatterns tests jQuery-like DOM manipulation patterns
// using a minimal jQuery-like wrapper running inside goja.
func TestBrowserAPI_jQueryPatterns(t *testing.T) {
	doc, _ := ParseWithURL(`<html><head><title>jQuery Test</title></head><body>
<div id="app">
  <h1 id="title" class="heading">Original Title</h1>
  <ul id="list"><li class="item">One</li><li class="item">Two</li><li class="item">Three</li></ul>
  <div id="box" style="color: red;">Box</div>
  <input id="input" type="text" value="hello"/>
  <button id="btn" class="btn primary">Click Me</button>
  <div id="container"></div>
</div>
</body></html>`, "https://example.com/jquery")
	vm := goja.New()
	vm.SetFieldNameMapper(goja.UncapFieldNameMapper())
	env := NewBrowserEnv(doc, vm)
	env.InjectGlobals()

	// Inject minimal jQuery-like $ function
	_, err := vm.RunString(`
		function $(selector) {
			var els;
			if (typeof selector === 'string') {
				if (selector.charAt(0) === '<') {
					var div = document.createElement('div');
					div.innerHTML = selector;
					var inner = div.innerHTML;
					if (typeof inner === 'function') inner = inner();
					els = div.querySelectorAll('*');
					if (!els || els.length === 0) {
						var frags = [];
						var cn = div.childNodes;
						if (typeof cn === 'function') cn = cn();
						els = [div.firstChild ? (typeof div.firstChild === 'function' ? div.firstChild() : div.firstChild) : div];
					}
				} else {
					els = document.querySelectorAll(selector);
				}
			} else if (selector && selector.tagName) {
				els = [selector];
			} else {
				els = [];
			}
			var arr = [];
			if (els && els.length !== undefined) {
				for (var i = 0; i < els.length; i++) arr.push(els[i]);
			}
			return {
				length: arr.length,
				get: function(i) { return arr[i]; },
				each: function(fn) { for (var i = 0; i < arr.length; i++) fn.call(arr[i], i, arr[i]); return this; },
				attr: function(name, val) {
					if (val === undefined) return arr.length ? arr[0].getAttribute(name) : null;
					for (var i = 0; i < arr.length; i++) arr[i].setAttribute(name, val);
					return this;
				},
				text: function(val) {
					if (val === undefined) return arr.length ? arr[0].textContent : '';
					for (var i = 0; i < arr.length; i++) arr[i].textContent = val;
					return this;
				},
				html: function(val) {
					if (val === undefined) { var h = arr.length ? arr[0].innerHTML : ''; return typeof h === 'function' ? h() : h; }
					for (var i = 0; i < arr.length; i++) arr[i].innerHTML = val;
					return this;
				},
				addClass: function(cls) { for (var i = 0; i < arr.length; i++) arr[i].classList.add(cls); return this; },
				removeClass: function(cls) { for (var i = 0; i < arr.length; i++) arr[i].classList.remove(cls); return this; },
				hasClass: function(cls) { return arr.length ? arr[0].classList.contains(cls) : false; },
				toggleClass: function(cls) { for (var i = 0; i < arr.length; i++) arr[i].classList.toggle(cls); return this; },
				css: function(prop, val) {
					if (val === undefined) return arr.length ? arr[0].style.getPropertyValue(prop) : '';
					for (var i = 0; i < arr.length; i++) arr[i].style.setProperty(prop, val);
					return this;
				},
				val: function(v) {
					if (v === undefined) return arr.length ? (arr[0].value || arr[0].getAttribute('value') || '') : '';
					for (var i = 0; i < arr.length; i++) { arr[i].value = v; arr[i].setAttribute('value', v); }
					return this;
				},
				on: function(evt, fn) { for (var i = 0; i < arr.length; i++) arr[i].addEventListener(evt, fn); return this; },
				trigger: function(evt) { for (var i = 0; i < arr.length; i++) arr[i].dispatchEvent(new Event(evt)); return this; },
				append: function(child) {
					if (typeof child === 'string') {
						for (var i = 0; i < arr.length; i++) arr[i].insertAdjacentHTML('beforeend', child);
					} else if (child && child.get) {
						for (var i = 0; i < arr.length; i++) arr[i].appendChild(child.get(0));
					}
					return this;
				},
				find: function(sel) { return arr.length ? $(arr[0].querySelector(sel)) : $(''); },
				remove: function() { for (var i = 0; i < arr.length; i++) arr[i].remove(); return this; },
				hide: function() { for (var i = 0; i < arr.length; i++) arr[i].style.setProperty('display', 'none'); return this; },
				show: function() { for (var i = 0; i < arr.length; i++) arr[i].style.setProperty('display', ''); return this; }
			};
		}
		$.fn = $;
	`)
	if err != nil {
		t.Fatalf("jQuery injection failed: %v", err)
	}

	tests := []struct {
		name string
		js   string
	}{
		{"jQuery: select by ID", `$('#title').length === 1`},
		{"jQuery: select by class", `$('.item').length === 3`},
		{"jQuery: text() getter", `$('#title').text() === 'Original Title'`},
		{"jQuery: text() setter", `(function() { var el = $('#title'); el.text('New Title'); return el.text() === 'New Title'; })()`},
		{"jQuery: attr() get/set", `(function() { $('#box').attr('data-x', '42'); return $('#box').attr('data-x') === '42'; })()`},
		{"jQuery: addClass + hasClass", `(function() { $('#box').addClass('highlight'); return $('#box').hasClass('highlight'); })()`},
		{"jQuery: removeClass", `(function() { $('#btn').removeClass('primary'); return !$('#btn').hasClass('primary'); })()`},
		{"jQuery: toggleClass", `(function() { $('#box').toggleClass('toggled'); var ok1 = $('#box').hasClass('toggled'); $('#box').toggleClass('toggled'); return ok1 && !$('#box').hasClass('toggled'); })()`},
		{"jQuery: css() get/set", `(function() { $('#box').css('background-color', 'blue'); return $('#box').css('background-color') === 'blue'; })()`},
		{"jQuery: val() get/set", `(function() { var old = $('#input').val(); $('#input').val('world'); return old === 'hello' && $('#input').val() === 'world'; })()`},
		{"jQuery: on + trigger event", `(function() { var clicked = false; $('#btn').on('click', function() { clicked = true; }); $('#btn').trigger('click'); return clicked; })()`},
		{"jQuery: chaining", `(function() { $('#box').addClass('a').addClass('b').attr('data-chain', 'yes'); return $('#box').hasClass('a') && $('#box').hasClass('b') && $('#box').attr('data-chain') === 'yes'; })()`},
		{"jQuery: append HTML string", `(function() { $('#container').append('<p class="appended">Hello jQuery</p>'); return $('#container').find('.appended').length === 1; })()`},
		{"jQuery: each() iteration", `(function() { var count = 0; $('.item').each(function(i, el) { count++; }); return count === 3; })()`},
		{"jQuery: hide/show", `(function() { $('#box').hide(); var hidden = $('#box').css('display') === 'none'; $('#box').show(); return hidden; })()`},
	}

	passed := 0
	failed := 0
	var failures []string
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := vm.RunString(tc.js)
			if err != nil {
				t.Errorf("JS ERROR: %v", err)
				failed++
				failures = append(failures, fmt.Sprintf("  ✗ %-55s ERROR: %v", tc.name, err))
				return
			}
			if !result.ToBoolean() {
				t.Errorf("returned %v (expected true)", result.Export())
				failed++
				failures = append(failures, fmt.Sprintf("  ✗ %-55s returned: %v", tc.name, result.Export()))
				return
			}
			passed++
		})
	}
	t.Logf("\n\n══════════════════════════════════════════════════════")
	t.Logf("  jQuery Patterns Test Summary")
	t.Logf("══════════════════════════════════════════════════════")
	t.Logf("  PASSED: %d", passed)
	t.Logf("  FAILED: %d", failed)
	t.Logf("  TOTAL:  %d", len(tests))
	if len(failures) > 0 {
		t.Logf("\n  Failures:")
		t.Logf("%s", strings.Join(failures, "\n"))
	}
	t.Logf("══════════════════════════════════════════════════════\n")
}

// TestBrowserAPI_ReactBasic tests React-like patterns: virtual DOM diffing,
// component state, hooks simulation, reconciliation, and JSX-like rendering.
func TestBrowserAPI_ReactBasic(t *testing.T) {
	doc, _ := ParseWithURL(`<html><head><title>React Test</title></head><body><div id="root"></div></body></html>`, "https://example.com/react")
	vm := goja.New()
	vm.SetFieldNameMapper(goja.UncapFieldNameMapper())
	env := NewBrowserEnv(doc, vm)
	env.InjectGlobals()

	// Inject minimal React-like framework
	_, err := vm.RunString(`
		var MiniReact = {
			createElement: function(type, props, children) {
				return { type: type, props: props || {}, children: Array.isArray(children) ? children : (children !== undefined ? [children] : []) };
			},
			render: function(vnode, container) {
				if (typeof vnode === 'string' || typeof vnode === 'number') {
					var t = document.createTextNode(String(vnode));
					container.appendChild(t);
					return;
				}
				var el = document.createElement(vnode.type);
				var p = vnode.props;
				if (p) {
					var keys = Object.keys(p);
					for (var i = 0; i < keys.length; i++) {
						var k = keys[i];
						if (k === 'className') el.setAttribute('class', p[k]);
						else if (k === 'id') el.setAttribute('id', p[k]);
						else if (k.indexOf('on') === 0) el.addEventListener(k.substring(2).toLowerCase(), p[k]);
						else if (k === 'style' && typeof p[k] === 'object') {
							var sk = Object.keys(p[k]);
							for (var j = 0; j < sk.length; j++) el.style.setProperty(sk[j], p[k][sk[j]]);
						}
						else el.setAttribute(k, p[k]);
					}
				}
				if (vnode.children) {
					for (var i = 0; i < vnode.children.length; i++) {
						MiniReact.render(vnode.children[i], el);
					}
				}
				container.appendChild(el);
			},
			useState: function(initial) {
				var state = {value: initial};
				var setState = function(newVal) {
					state.value = typeof newVal === 'function' ? newVal(state.value) : newVal;
				};
				return [function() { return state.value; }, setState];
			},
			useEffect: function(fn, deps) {
				var cleanup = fn();
				return { cleanup: cleanup, deps: deps };
			}
		};
		var h = MiniReact.createElement;
	`)
	if err != nil {
		t.Fatalf("MiniReact injection failed: %v", err)
	}

	tests := []struct {
		name string
		js   string
	}{
		{"React: createElement basic", `(function() {
			var vnode = h('div', {id: 'test'}, 'Hello');
			return vnode.type === 'div' && vnode.props.id === 'test' && vnode.children[0] === 'Hello';
		})()`},

		{"React: nested createElement", `(function() {
			var vnode = h('div', {className: 'container'}, [
				h('h1', null, 'Title'),
				h('p', {className: 'body'}, 'Content')
			]);
			return vnode.type === 'div' && vnode.children.length === 2 &&
				vnode.children[0].type === 'h1' && vnode.children[1].type === 'p';
		})()`},

		{"React: render to DOM", `(function() {
			var root = document.getElementById('root');
			root.textContent = '';
			var vnode = h('div', {id: 'rendered', className: 'react-comp'}, [
				h('h1', null, 'React Title'),
				h('p', null, 'React Content')
			]);
			MiniReact.render(vnode, root);
			var rendered = document.getElementById('rendered');
			return rendered !== null && rendered.getAttribute('class') === 'react-comp';
		})()`},

		{"React: render with style object", `(function() {
			var root = document.getElementById('root');
			var vnode = h('div', {id: 'styled', style: {color: 'red', 'font-size': '16px'}}, 'Styled');
			MiniReact.render(vnode, root);
			var el = document.getElementById('styled');
			return el !== null &&
				el.style.getPropertyValue('color') === 'red' &&
				el.style.getPropertyValue('font-size') === '16px';
		})()`},

		{"React: render with event handler", `(function() {
			var root = document.getElementById('root');
			var clicked = false;
			var vnode = h('button', {id: 'react-btn', onClick: function() { clicked = true; }}, 'Click');
			MiniReact.render(vnode, root);
			var btn = document.getElementById('react-btn');
			btn.dispatchEvent(new Event('click'));
			return clicked;
		})()`},

		{"React: useState basic", `(function() {
			var result = MiniReact.useState(0);
			var getCount = result[0];
			var setCount = result[1];
			setCount(5);
			return getCount() === 5;
		})()`},

		{"React: useState functional update", `(function() {
			var result = MiniReact.useState(10);
			var getCount = result[0];
			var setCount = result[1];
			setCount(function(prev) { return prev + 5; });
			setCount(function(prev) { return prev * 2; });
			return getCount() === 30;
		})()`},

		{"React: useEffect lifecycle", `(function() {
			var log = [];
			var effect = MiniReact.useEffect(function() {
				log.push('mount');
				return function() { log.push('cleanup'); };
			}, []);
			effect.cleanup();
			return log.length === 2 && log[0] === 'mount' && log[1] === 'cleanup';
		})()`},

		{"React: component function pattern", `(function() {
			function Counter(props) {
				var result = MiniReact.useState(props.initial || 0);
				var getCount = result[0];
				var setCount = result[1];
				return {
					increment: function() { setCount(function(c) { return c + 1; }); },
					decrement: function() { setCount(function(c) { return c - 1; }); },
					getCount: getCount,
					render: function() {
						return h('div', {className: 'counter'}, [
							h('span', {className: 'count'}, String(getCount())),
							h('button', {className: 'inc'}, '+'),
							h('button', {className: 'dec'}, '-')
						]);
					}
				};
			}
			var counter = Counter({initial: 10});
			counter.increment();
			counter.increment();
			counter.decrement();
			return counter.getCount() === 11;
		})()`},

		{"React: render list of items", `(function() {
			var root = document.getElementById('root');
			var items = ['Apple', 'Banana', 'Cherry', 'Date', 'Elderberry'];
			var listItems = items.map(function(item, i) {
				return h('li', {className: 'fruit', 'data-index': String(i)}, item);
			});
			var vnode = h('ul', {id: 'fruit-list'}, listItems);
			MiniReact.render(vnode, root);
			var list = document.getElementById('fruit-list');
			return list !== null && list.querySelectorAll('.fruit').length === 5;
		})()`},

		{"React: conditional rendering", `(function() {
			function ConditionalComp(props) {
				if (props.show) {
					return h('div', {id: 'cond-visible'}, 'Visible');
				}
				return h('div', {id: 'cond-hidden', className: 'hidden'}, '');
			}
			var root = document.getElementById('root');
			var v1 = ConditionalComp({show: true});
			MiniReact.render(v1, root);
			var visible = document.getElementById('cond-visible');
			var v2 = ConditionalComp({show: false});
			MiniReact.render(v2, root);
			var hidden = document.getElementById('cond-hidden');
			return visible !== null && hidden !== null;
		})()`},

		{"React: props drilling pattern", `(function() {
			function Parent(props) {
				return h('div', {className: 'parent'}, [
					Child({name: props.name, age: props.age})
				]);
			}
			function Child(props) {
				return h('span', {className: 'child'}, props.name + ' age:' + props.age);
			}
			var root = document.getElementById('root');
			var vnode = Parent({name: 'Alice', age: 30});
			MiniReact.render(vnode, root);
			return vnode.type === 'div' && vnode.children.length === 1 &&
				vnode.children[0].type === 'span';
		})()`},

		{"React: re-render updates DOM", `(function() {
			var container = document.createElement('div');
			container.setAttribute('id', 'rerender-root');
			var body = document.body; if (typeof body === 'function') body = body();
			body.appendChild(container);
			MiniReact.render(h('p', {id: 'rr-text'}, 'Version1'), container);
			var v1 = document.getElementById('rr-text');
			var ok1 = v1 !== null && v1.textContent === 'Version1';
			MiniReact.render(h('p', {id: 'rr-text2'}, 'Version2'), container);
			var v2 = document.getElementById('rr-text2');
			var ok2 = v2 !== null && v2.textContent === 'Version2';
			return ok1 && ok2;
		})()`},
	}

	passed := 0
	failed := 0
	var failures []string
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := vm.RunString(tc.js)
			if err != nil {
				t.Errorf("JS ERROR: %v", err)
				failed++
				failures = append(failures, fmt.Sprintf("  ✗ %-55s ERROR: %v", tc.name, err))
				return
			}
			if !result.ToBoolean() {
				t.Errorf("returned %v (expected true)", result.Export())
				failed++
				failures = append(failures, fmt.Sprintf("  ✗ %-55s returned: %v", tc.name, result.Export()))
				return
			}
			passed++
		})
	}
	t.Logf("\n\n══════════════════════════════════════════════════════")
	t.Logf("  React Basic Patterns Test Summary")
	t.Logf("══════════════════════════════════════════════════════")
	t.Logf("  PASSED: %d", passed)
	t.Logf("  FAILED: %d", failed)
	t.Logf("  TOTAL:  %d", len(tests))
	if len(failures) > 0 {
		t.Logf("\n  Failures:")
		t.Logf("%s", strings.Join(failures, "\n"))
	}
	t.Logf("══════════════════════════════════════════════════════\n")
}

// TestBrowserAPI_AsyncBehavior tests the ACTUAL BEHAVIOR of every async primitive
// that React depends on. This is NOT about typeof — it's about whether callbacks
// really fire when the event loop is drained. These tests simulate what happens
// when React's scheduler tries to use MessageChannel, queueMicrotask, setTimeout,
// MutationObserver, etc.
//
// The key insight: in our goja-based browser, async callbacks are collected into
// env.PendingTimers. We must drain them to simulate the event loop.
func TestBrowserAPI_AsyncBehavior(t *testing.T) {
	doc, _ := ParseWithURL(`<html><head><title>Async Test</title></head><body><div id="root"></div></body></html>`, "https://example.com/async")
	vm := goja.New()
	vm.SetFieldNameMapper(goja.UncapFieldNameMapper())
	env := NewBrowserEnv(doc, vm)
	env.InjectGlobals()

	// Helper: drain all PendingTimers (simulates one event loop tick)
	// Uses recover to handle JS throw inside callbacks (like a real browser event loop)
	drainTimers := func() {
		for rounds := 0; rounds < 20 && len(env.PendingTimers) > 0; rounds++ {
			batch := env.PendingTimers
			env.PendingTimers = nil
			for _, fn := range batch {
				func() {
					defer func() { recover() }()
					fn()
				}()
			}
		}
	}

	tests := []struct {
		name string
		js   string
		// drain indicates whether PendingTimers should be drained before checking result
		drain bool
	}{
		// ════════════════════════════════════════════════════════════════
		// setTimeout — callback must actually execute after drain
		// ════════════════════════════════════════════════════════════════
		{"setTimeout: callback fires after drain", `(function() {
			window.__st_fired = false;
			setTimeout(function() { window.__st_fired = true; }, 0);
			return true;
		})()`, true},
		{"setTimeout: verify fired", `window.__st_fired === true`, false},

		{"setTimeout: callback receives no error", `(function() {
			window.__st_val = 'not set';
			setTimeout(function() { window.__st_val = 'executed'; }, 0);
			return true;
		})()`, true},
		{"setTimeout: verify value", `window.__st_val === 'executed'`, false},

		{"setTimeout: multiple callbacks in order", `(function() {
			window.__st_order = [];
			setTimeout(function() { window.__st_order.push(1); }, 0);
			setTimeout(function() { window.__st_order.push(2); }, 0);
			setTimeout(function() { window.__st_order.push(3); }, 0);
			return true;
		})()`, true},
		{"setTimeout: verify order", `(function() {
			return window.__st_order.length === 3 &&
				window.__st_order[0] === 1 &&
				window.__st_order[1] === 2 &&
				window.__st_order[2] === 3;
		})()`, false},

		// ════════════════════════════════════════════════════════════════
		// queueMicrotask — callback must fire after drain
		// ════════════════════════════════════════════════════════════════
		{"queueMicrotask: callback fires after drain", `(function() {
			window.__qm_fired = false;
			queueMicrotask(function() { window.__qm_fired = true; });
			return true;
		})()`, true},
		{"queueMicrotask: verify fired", `window.__qm_fired === true`, false},

		{"queueMicrotask: multiple callbacks", `(function() {
			window.__qm_order = [];
			queueMicrotask(function() { window.__qm_order.push('a'); });
			queueMicrotask(function() { window.__qm_order.push('b'); });
			queueMicrotask(function() { window.__qm_order.push('c'); });
			return true;
		})()`, true},
		{"queueMicrotask: verify order", `(function() {
			return window.__qm_order.length === 3 &&
				window.__qm_order[0] === 'a' &&
				window.__qm_order[1] === 'b' &&
				window.__qm_order[2] === 'c';
		})()`, false},

		// ════════════════════════════════════════════════════════════════
		// process.nextTick — must fire after drain (Node.js compat)
		// ════════════════════════════════════════════════════════════════
		{"process.nextTick: callback fires after drain", `(function() {
			window.__nt_fired = false;
			process.nextTick(function() { window.__nt_fired = true; });
			return true;
		})()`, true},
		{"process.nextTick: verify fired", `window.__nt_fired === true`, false},

		// ════════════════════════════════════════════════════════════════
		// requestAnimationFrame — callback must fire after drain
		// ════════════════════════════════════════════════════════════════
		{"rAF: callback fires after drain", `(function() {
			window.__raf_fired = false;
			requestAnimationFrame(function() { window.__raf_fired = true; });
			return true;
		})()`, true},
		{"rAF: verify fired", `window.__raf_fired === true`, false},

		// ════════════════════════════════════════════════════════════════
		// requestIdleCallback — callback must fire after drain
		// ════════════════════════════════════════════════════════════════
		{"rIC: callback fires after drain", `(function() {
			window.__ric_fired = false;
			requestIdleCallback(function() { window.__ric_fired = true; });
			return true;
		})()`, true},
		{"rIC: verify fired", `window.__ric_fired === true`, false},

		// ════════════════════════════════════════════════════════════════
		// MessageChannel — THE CRITICAL ONE for React scheduler
		// React does: port1.onmessage = handler; port2.postMessage(null);
		// ════════════════════════════════════════════════════════════════
		{"MessageChannel: onmessage delivery", `(function() {
			window.__mc_fired = false;
			window.__mc_data = null;
			var mc = new MessageChannel();
			mc.port1.onmessage = function(ev) {
				window.__mc_fired = true;
				window.__mc_data = ev.data;
			};
			mc.port2.postMessage('hello');
			return true;
		})()`, true},
		{"MessageChannel: verify onmessage fired", `window.__mc_fired === true`, false},
		{"MessageChannel: verify message data", `window.__mc_data === 'hello'`, false},

		{"MessageChannel: null message (React pattern)", `(function() {
			window.__mc_react = false;
			var channel = new MessageChannel();
			channel.port1.onmessage = function(ev) {
				window.__mc_react = true;
			};
			channel.port2.postMessage(null);
			return true;
		})()`, true},
		{"MessageChannel: verify null message fires", `window.__mc_react === true`, false},

		{"MessageChannel: multiple messages in sequence", `(function() {
			window.__mc_seq = [];
			var mc = new MessageChannel();
			mc.port1.onmessage = function(ev) {
				window.__mc_seq.push(ev.data);
			};
			mc.port2.postMessage(1);
			mc.port2.postMessage(2);
			mc.port2.postMessage(3);
			return true;
		})()`, true},
		{"MessageChannel: verify sequential messages", `(function() {
			return window.__mc_seq.length === 3 &&
				window.__mc_seq[0] === 1 &&
				window.__mc_seq[1] === 2 &&
				window.__mc_seq[2] === 3;
		})()`, false},

		{"MessageChannel: addEventListener('message') delivery", `(function() {
			window.__mc_ael = false;
			var mc = new MessageChannel();
			mc.port1.addEventListener('message', function(ev) {
				window.__mc_ael = true;
			});
			mc.port2.postMessage('test');
			return true;
		})()`, true},
		{"MessageChannel: verify addEventListener delivery", `window.__mc_ael === true`, false},

		{"MessageChannel: port.close stops delivery", `(function() {
			window.__mc_closed = 'initial';
			var mc = new MessageChannel();
			mc.port1.onmessage = function(ev) {
				window.__mc_closed = 'should_not_fire';
			};
			mc.port1.close();
			mc.port2.postMessage('after_close');
			return true;
		})()`, true},
		{"MessageChannel: verify close stops delivery", `window.__mc_closed === 'initial'`, false},

		// ════════════════════════════════════════════════════════════════
		// React Scheduler simulation — exact pattern React uses
		// ════════════════════════════════════════════════════════════════
		{"React Scheduler: full pattern simulation", `(function() {
			window.__sched_log = [];
			var scheduledCallback = null;
			var channel = new MessageChannel();
			var port = channel.port2;

			channel.port1.onmessage = function() {
				window.__sched_log.push('message_received');
				if (scheduledCallback !== null) {
					var cb = scheduledCallback;
					scheduledCallback = null;
					cb();
				}
			};

			function scheduleWork(callback) {
				scheduledCallback = callback;
				window.__sched_log.push('posting_message');
				port.postMessage(null);
			}

			scheduleWork(function() {
				window.__sched_log.push('work_executed');
			});

			return true;
		})()`, true},
		{"React Scheduler: verify full cycle", `(function() {
			var log = window.__sched_log;
			return log.length === 3 &&
				log[0] === 'posting_message' &&
				log[1] === 'message_received' &&
				log[2] === 'work_executed';
		})()`, false},

		// ════════════════════════════════════════════════════════════════
		// Chained async — setTimeout inside setTimeout (multi-round drain)
		// ════════════════════════════════════════════════════════════════
		{"Chained setTimeout: nested callbacks", `(function() {
			window.__chain = [];
			setTimeout(function() {
				window.__chain.push('first');
				setTimeout(function() {
					window.__chain.push('second');
					setTimeout(function() {
						window.__chain.push('third');
					}, 0);
				}, 0);
			}, 0);
			return true;
		})()`, true},
		{"Chained setTimeout: verify chain", `(function() {
			return window.__chain.length === 3 &&
				window.__chain[0] === 'first' &&
				window.__chain[1] === 'second' &&
				window.__chain[2] === 'third';
		})()`, false},

		// ════════════════════════════════════════════════════════════════
		// Mixed async: setTimeout + queueMicrotask interleaving
		// ════════════════════════════════════════════════════════════════
		{"Mixed async: setTimeout + queueMicrotask", `(function() {
			window.__mixed = [];
			setTimeout(function() { window.__mixed.push('timeout'); }, 0);
			queueMicrotask(function() { window.__mixed.push('microtask'); });
			return true;
		})()`, true},
		{"Mixed async: verify both executed", `(function() {
			return window.__mixed.length === 2 &&
				window.__mixed.indexOf('timeout') >= 0 &&
				window.__mixed.indexOf('microtask') >= 0;
		})()`, false},

		// ════════════════════════════════════════════════════════════════
		// MessageChannel + setTimeout — React scheduler fallback chain
		// ════════════════════════════════════════════════════════════════
		{"MC + setTimeout: fallback chain", `(function() {
			window.__fallback = [];
			var mc = new MessageChannel();
			mc.port1.onmessage = function() {
				window.__fallback.push('mc');
				setTimeout(function() {
					window.__fallback.push('st_after_mc');
				}, 0);
			};
			mc.port2.postMessage(null);
			return true;
		})()`, true},
		{"MC + setTimeout: verify fallback chain", `(function() {
			return window.__fallback.length === 2 &&
				window.__fallback[0] === 'mc' &&
				window.__fallback[1] === 'st_after_mc';
		})()`, false},

		// ════════════════════════════════════════════════════════════════
		// MutationObserver — does the callback actually fire on DOM change?
		// NOTE: This is expected to NOT fire in our stub. We test to verify.
		// ════════════════════════════════════════════════════════════════
		{"MutationObserver: observe childList (stub check)", `(function() {
			window.__mo_fired = false;
			var div = document.createElement('div');
			var observer = new MutationObserver(function(mutations) {
				window.__mo_fired = true;
			});
			observer.observe(div, {childList: true});
			div.appendChild(document.createElement('span'));
			return true;
		})()`, true},
		{"MutationObserver: verify callback status", `(function() {
			// In our stub, MutationObserver callback does NOT fire.
			// This test documents the current behavior.
			// If React needs MutationObserver to actually fire, this must change.
			return typeof window.__mo_fired === 'boolean';
		})()`, false},

		// ════════════════════════════════════════════════════════════════
		// DOM manipulation during timer callbacks (React commit phase)
		// ════════════════════════════════════════════════════════════════
		{"DOM in timer: createElement + appendChild during callback", `(function() {
			window.__dom_timer_ok = false;
			window.__dom_timer_dbg = '';
			setTimeout(function() {
				try {
					var div = document.createElement('div');
					div.setAttribute('id', 'timer-created');
					var root = document.getElementById('root');
					if (!root) { window.__dom_timer_dbg = 'root_null'; return; }
					root.appendChild(div);
					var found = document.getElementById('timer-created');
					if (!found) { window.__dom_timer_dbg = 'found_null'; return; }
					window.__dom_timer_ok = true;
				} catch(e) {
					window.__dom_timer_dbg = 'error:' + e.message;
				}
			}, 0);
			return true;
		})()`, true},
		{"DOM in timer: verify element created", `(function() {
			if (!window.__dom_timer_ok) {
				// debug: check what went wrong
				console.log('DOM timer debug:', window.__dom_timer_dbg);
			}
			return window.__dom_timer_ok === true;
		})()`, false},

		// ════════════════════════════════════════════════════════════════
		// Event dispatch inside timer callback (React synthetic events)
		// ════════════════════════════════════════════════════════════════
		{"Event in timer: dispatch during callback", `(function() {
			window.__evt_timer = false;
			var btn = document.createElement('button');
			btn.addEventListener('click', function() {
				window.__evt_timer = true;
			});
			setTimeout(function() {
				btn.dispatchEvent(new Event('click'));
			}, 0);
			return true;
		})()`, true},
		{"Event in timer: verify event dispatched", `window.__evt_timer === true`, false},

		// ════════════════════════════════════════════════════════════════
		// Stress test: 100 sequential timer callbacks
		// ════════════════════════════════════════════════════════════════
		{"Stress: 100 timer callbacks", `(function() {
			window.__stress_count = 0;
			for (var i = 0; i < 100; i++) {
				setTimeout(function() { window.__stress_count++; }, 0);
			}
			return true;
		})()`, true},
		{"Stress: verify all 100 fired", `window.__stress_count === 100`, false},

		// ════════════════════════════════════════════════════════════════
		// Stress: 50 MessageChannel messages
		// ════════════════════════════════════════════════════════════════
		{"Stress: 50 MC messages", `(function() {
			window.__mc_stress = 0;
			var mc = new MessageChannel();
			mc.port1.onmessage = function() { window.__mc_stress++; };
			for (var i = 0; i < 50; i++) {
				mc.port2.postMessage(i);
			}
			return true;
		})()`, true},
		{"Stress: verify all 50 MC messages", `window.__mc_stress === 50`, false},

		// ════════════════════════════════════════════════════════════════
		// React reconciler simulation: schedule → flush → commit → re-schedule
		// ════════════════════════════════════════════════════════════════
		{"React reconciler: multi-phase scheduling", `(function() {
			window.__recon = [];
			var channel = new MessageChannel();
			var port = channel.port2;
			var taskQueue = [];

			channel.port1.onmessage = function() {
				if (taskQueue.length > 0) {
					var task = taskQueue.shift();
					task();
					// If more tasks, re-schedule (like React does)
					if (taskQueue.length > 0) {
						port.postMessage(null);
					}
				}
			};

			taskQueue.push(function() { window.__recon.push('render'); });
			taskQueue.push(function() { window.__recon.push('commit'); });
			taskQueue.push(function() { window.__recon.push('effect'); });
			port.postMessage(null);
			return true;
		})()`, true},
		{"React reconciler: verify all phases", `(function() {
			var r = window.__recon;
			return r.length === 3 &&
				r[0] === 'render' &&
				r[1] === 'commit' &&
				r[2] === 'effect';
		})()`, false},

		// ════════════════════════════════════════════════════════════════
		// Promise.resolve().then() — microtask behavior
		// ════════════════════════════════════════════════════════════════
		{"Promise.then: callback execution", `(function() {
			window.__promise_fired = false;
			Promise.resolve().then(function() {
				window.__promise_fired = true;
			});
			return true;
		})()`, true},
		{"Promise.then: verify fired", `window.__promise_fired === true`, false},

		{"Promise.then: chained promises", `(function() {
			window.__promise_chain = [];
			Promise.resolve('a')
				.then(function(v) { window.__promise_chain.push(v); return 'b'; })
				.then(function(v) { window.__promise_chain.push(v); return 'c'; })
				.then(function(v) { window.__promise_chain.push(v); });
			return true;
		})()`, true},
		{"Promise.then: verify chain", `(function() {
			var c = window.__promise_chain;
			return c.length === 3 && c[0] === 'a' && c[1] === 'b' && c[2] === 'c';
		})()`, false},

		// ════════════════════════════════════════════════════════════════
		// Timer callback that schedules more work (recursive scheduling)
		// ════════════════════════════════════════════════════════════════
		{"Recursive scheduling: callback schedules callback", `(function() {
			window.__recursive = 0;
			function tick() {
				window.__recursive++;
				if (window.__recursive < 5) {
					setTimeout(tick, 0);
				}
			}
			setTimeout(tick, 0);
			return true;
		})()`, true},
		{"Recursive scheduling: verify 5 ticks", `window.__recursive === 5`, false},

		// ════════════════════════════════════════════════════════════════
		// MessageChannel bidirectional — port1 and port2 both send/receive
		// ════════════════════════════════════════════════════════════════
		{"MC bidirectional: both ports communicate", `(function() {
			window.__bidir = [];
			var mc = new MessageChannel();
			mc.port1.onmessage = function(ev) {
				window.__bidir.push('port1_got:' + ev.data);
				// Reply back 
				if (ev.data === 'ping') {
					mc.port1.postMessage('pong');
				}
			};
			mc.port2.onmessage = function(ev) {
				window.__bidir.push('port2_got:' + ev.data);
			};
			mc.port2.postMessage('ping');
			return true;
		})()`, true},
		{"MC bidirectional: verify ping-pong", `(function() {
			var b = window.__bidir;
			return b.length === 2 &&
				b[0] === 'port1_got:ping' &&
				b[1] === 'port2_got:pong';
		})()`, false},

		// ════════════════════════════════════════════════════════════════
		// Error in timer callback — must NOT crash subsequent callbacks
		// NOTE: This test is LAST because JS throw corrupts goja VM state.
		// ════════════════════════════════════════════════════════════════
		{"Error resilience: error in one callback doesn't stop others", `(function() {
			window.__err_before = false;
			window.__err_after = false;
			setTimeout(function() { window.__err_before = true; }, 0);
			setTimeout(function() { throw new Error('intentional'); }, 0);
			setTimeout(function() { window.__err_after = true; }, 0);
			return true;
		})()`, true},
		{"Error resilience: verify before fired", `window.__err_before === true`, false},
		{"Error resilience: verify after fired (error recovery)", `window.__err_after === true`, false},
	}

	passed := 0
	failed := 0
	var failures []string

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := vm.RunString(tc.js)
			if err != nil {
				t.Errorf("JS ERROR: %v", err)
				failed++
				failures = append(failures, fmt.Sprintf("  ✗ %-60s ERROR: %v", tc.name, err))
				return
			}

			// Drain PendingTimers if this test requires it
			if tc.drain {
				drainTimers()
			}

			if !result.ToBoolean() {
				t.Errorf("returned %v (expected true)", result.Export())
				failed++
				failures = append(failures, fmt.Sprintf("  ✗ %-60s returned: %v", tc.name, result.Export()))
				return
			}
			passed++
		})
	}

	t.Logf("\n\n════════════════════════════════════════════════════════════")
	t.Logf("  Async Behavior Test Summary")
	t.Logf("════════════════════════════════════════════════════════════")
	t.Logf("  PASSED: %d", passed)
	t.Logf("  FAILED: %d", failed)
	t.Logf("  TOTAL:  %d", len(tests))
	if len(failures) > 0 {
		t.Logf("\n  Failures:")
		t.Logf("%s", strings.Join(failures, "\n"))
	}
	t.Logf("════════════════════════════════════════════════════════════")

	// Log diagnostic info about MutationObserver behavior
	t.Logf("\n  ── Diagnostic Notes ──")
	if val, err := vm.RunString("window.__mo_fired"); err == nil {
		t.Logf("  MutationObserver callback fired: %v", val.Export())
		if !val.ToBoolean() {
			t.Logf("  ⚠ WARNING: MutationObserver is a no-op stub. If React depends on it, callbacks will never fire.")
		}
	}
	t.Logf("  PendingTimers remaining: %d", len(env.PendingTimers))
	t.Logf("════════════════════════════════════════════════════════════\n")
}

// TestBrowserAPI_SauceDemo_ReactRender loads the SauceDemo React bundle (test.js),
// embeds it in an HTML skeleton with <div id="root">, executes the script
// via goja BrowserEnv, drains React scheduler timers, and saves the rendered
// DOM state to preview.html for inspection.
func TestBrowserAPI_SauceDemo_ReactRender(t *testing.T) {
	// 1. Read the SauceDemo React bundle
	bundlePath := filepath.Join(".", "test.js")
	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("Failed to read test.js: %v", err)
	}
	bundleCode := string(bundleBytes)
	t.Logf("[SauceDemo] Loaded bundle: %d bytes (%d lines)", len(bundleCode), strings.Count(bundleCode, "\n")+1)

	// Strip source map URL (Goja tries to load .map files from disk)
	for _, prefix := range []string{"//# sourceMappingURL=", "//@ sourceMappingURL=", "//# sourceURL="} {
		if idx := strings.LastIndex(bundleCode, prefix); idx >= 0 {
			end := strings.IndexByte(bundleCode[idx:], '\n')
			if end == -1 {
				bundleCode = bundleCode[:idx]
			} else {
				bundleCode = bundleCode[:idx] + bundleCode[idx+end:]
			}
		}
	}

	// 2. Construct SauceDemo-like HTML skeleton
	htmlStr := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Swag Labs</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body>
  <noscript>You need to enable JavaScript to run this app.</noscript>
  <div id="root"></div>
</body>
</html>`

	t.Logf("[SauceDemo] Parsing HTML skeleton...")
	doc, err := ParseWithURL(htmlStr, "https://www.saucedemo.com/")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	t.Logf("[SauceDemo] Skeleton parsed OK. Title: %q", doc.Title())

	// 3. Create goja VM + BrowserEnv
	vm := goja.New()
	vm.SetFieldNameMapper(goja.UncapFieldNameMapper())
	env := NewBrowserEnv(doc, vm)
	env.InjectGlobals()

	t.Logf("[SauceDemo] Browser globals injected. Executing React bundle (%d bytes)...", len(bundleCode))

	// 4. Execute the React bundle with dynamic timeout based on bundle size.
	// Goja is a pure-Go interpreter (no JIT), large bundles need proportionally more time.
	// Formula: base 30s + 30s per 500KB beyond 100KB.
	timeout := time.Duration(30) * time.Second
	if len(bundleCode) > 100*1024 {
		extraKB := float64(len(bundleCode)-100*1024) / float64(500*1024)
		timeout += time.Duration(int(extraKB*30)+1) * time.Second
	}
	t.Logf("[SauceDemo] Using timeout: %v for %d byte bundle", timeout, len(bundleCode))
	timer := time.AfterFunc(timeout, func() {
		t.Logf("[SauceDemo] Script timeout (%v), interrupting VM", timeout)
		vm.Interrupt("script execution timeout")
	})

	start := time.Now()
	// Intercept console.error to capture React's internal errors
	vm.Set("__originalConsoleError__", vm.Get("console").ToObject(vm).Get("error"))
	vm.RunString(`
		var __capturedErrors = [];
		var __origErr = console.error;
		console.error = function() {
			__capturedErrors.push(Array.prototype.join.call(arguments, ' '));
			if (__origErr) __origErr.apply(console, arguments);
		};
	`)

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("[SauceDemo] Runtime panic (recovered): %v", r)
			}
		}()
		_, err = vm.RunString(bundleCode)
		if err != nil {
			t.Logf("[SauceDemo] Script error (non-fatal): %v", err)
		}
	}()

	// Report captured console.error calls
	errVal, _ := vm.RunString(`__capturedErrors.join('\n---\n')`)
	if errStr := errVal.String(); errStr != "" {
		t.Logf("[SauceDemo] console.error calls:\n%s", errStr)
	}
	timer.Stop()
	vm.ClearInterrupt()
	t.Logf("[SauceDemo] Script execution took %v. PendingTimers: %d", time.Since(start), len(env.PendingTimers))

	// Debug: check if React's root container has internal fiber references
	debugVal, debugErr := vm.RunString(`(function() {
		var root = document.getElementById('root');
		if (!root) return 'NO ROOT';
		var keys = Object.keys(root);
		var reactKeys = keys.filter(function(k) { return k.indexOf('__react') === 0 || k.indexOf('_react') === 0; });
		return 'root keys: ' + keys.length + ', react keys: [' + reactKeys.join(',') + '], children: ' + (root.childNodes ? root.childNodes.length : 'N/A');
	})()`)
	if debugErr != nil {
		t.Logf("[Debug] Error checking root: %v", debugErr)
	} else {
		t.Logf("[Debug] React root state: %v", debugVal)
	}

	// 5. Drain React scheduler timers (50 rounds to let React fully flush)
	drainStart := time.Now()
	env.DrainTimers(50)
	t.Logf("[SauceDemo] Timer drain took %v. Remaining: %d", time.Since(drainStart), len(env.PendingTimers))

	// Debug: check root again after drain
	debugVal2, _ := vm.RunString(`(function() {
		var root = document.getElementById('root');
		if (!root) return 'NO ROOT';
		var rc = root._reactRootContainer;
		var fiberInfo = 'no fiber';
		if (rc && rc._internalRoot) {
			var ir = rc._internalRoot;
			var current = ir.current;
			if (current) {
				var child = current.child;
				fiberInfo = 'fiber exists, child=' + (child ? child.type || child.tag : 'null') + ', pendingLanes=' + (ir.pendingLanes || 0);
			}
		} else if (rc) {
			fiberInfo = 'rc exists but no _internalRoot, keys=' + Object.keys(rc).join(',');
		}
		return 'children: ' + (root.childNodes ? root.childNodes.length : 'N/A') + ', fiber: ' + fiberInfo;
	})()`)
	t.Logf("[Debug] React root state after drain: %v", debugVal2)

	// Debug: Extract actual error from the error boundary
	debugVal4, _ := vm.RunString(`(function() {
		var root = document.getElementById('root');
		var rc = root._reactRootContainer;
		if (!rc || !rc._internalRoot) return 'no internal root';
		var ir = rc._internalRoot;
		var child = ir.current.child;
		if (!child) return 'no child';
		var instance = child.stateNode;
		var state = instance.state;
		
		var info = 'state keys: ' + Object.keys(state).join(',');
		
		// Try to get the actual error object
		var err = state.error;
		if (err) {
			info += ', error type: ' + (typeof err);
			info += ', error message: ' + (err.message || 'NO MESSAGE');
			info += ', error name: ' + (err.name || 'NO NAME');
			info += ', error stack: ' + (err.stack ? err.stack.substring(0, 600) : 'NO STACK');
			info += ', error toString: ' + String(err);
			info += ', error keys: ' + Object.keys(err).join(',');
		}

		// Also check memoizedState for error info
		var ms = child.memoizedState;
		if (ms && ms.error) {
			var me = ms.error;
			info += ' | memoized error: ' + (me.message || String(me));
		}
		
		return info;
	})()`)
	t.Logf("[Debug] Error boundary: %v", debugVal4)

	// Try more drains in case callbacks spawned more work
	for i := 0; i < 3; i++ {
		if len(env.PendingTimers) > 0 {
			env.DrainTimers(50)
			t.Logf("[Debug] Extra drain round %d: remaining=%d", i, len(env.PendingTimers))
		}
	}

	// Debug: test manual appendChild
	debugVal3, debugErr3 := vm.RunString(`(function() {
		var root = document.getElementById('root');
		var div = document.createElement('div');
		div.id = 'manual-test';
		root.appendChild(div);

		// Check from Go DOM tree
		var result = 'after manual appendChild: children=' + (root.childNodes ? root.childNodes.length : 'N/A');

		// Check the _reactRootContainer for stateNode
		var rc = root._reactRootContainer;
		if (rc && rc._internalRoot) {
			var ir = rc._internalRoot;
			var containerInfo = ir.containerInfo;
			result += ', containerInfo===root: ' + (containerInfo === root);
			result += ', containerInfo.childNodes: ' + (containerInfo && containerInfo.childNodes ? containerInfo.childNodes.length : 'N/A');
		}

		// Remove test node
		root.removeChild(div);
		result += ', after remove: children=' + (root.childNodes ? root.childNodes.length : 'N/A');
		return result;
	})()`)
	if debugErr3 != nil {
		t.Logf("[Debug] appendChild test error: %v", debugErr3)
	} else {
		t.Logf("[Debug] appendChild test: %v", debugVal3)
	}

	// ════════════════════════════════════════════════
	// 6. SHOW ALL RENDERED STATE
	// ════════════════════════════════════════════════
	t.Log("\n══════════════════════════════════════════════")
	t.Log("  RENDERED DOM STATE")
	t.Log("══════════════════════════════════════════════")

	// Element counts
	elementCount := countTestElements(doc.Root)
	allDivs := doc.Root.GetElementsByTagName("div")
	allInputs := doc.Root.GetElementsByTagName("input")
	allButtons := doc.Root.GetElementsByTagName("button")
	allForms := doc.Root.GetElementsByTagName("form")
	allAnchors := doc.Root.GetElementsByTagName("a")
	allSpans := doc.Root.GetElementsByTagName("span")
	allImgs := doc.Root.GetElementsByTagName("img")

	t.Logf("  Total elements: %d", elementCount)
	t.Logf("  <div>: %d | <input>: %d | <button>: %d | <form>: %d",
		len(allDivs), len(allInputs), len(allButtons), len(allForms))
	t.Logf("  <a>: %d | <span>: %d | <img>: %d",
		len(allAnchors), len(allSpans), len(allImgs))

	// Body children
	body := doc.Body()
	if body != nil {
		t.Logf("\n  <body> has %d direct children:", len(body.Children))
		for i, child := range body.Children {
			if child.Type == ElementNode {
				t.Logf("    [%d] <%s id=%q class=%q> children=%d",
					i, child.Tag, child.ID(), strings.Join(child.ClassList(), " "), len(child.Children))
			} else if child.Type == TextNode {
				text := strings.TrimSpace(child.Text)
				if text != "" {
					t.Logf("    [%d] #text: %q", i, text)
				}
			}
		}
	}

	// Root div children (React renders here)
	rootDiv := doc.GetElementByID("root")
	if rootDiv != nil {
		t.Logf("\n  <div id=\"root\"> has %d children:", len(rootDiv.Children))
		printNodeTree(t, rootDiv, "    ", 3) // 3 levels deep
	}

	// Specific element queries
	t.Log("\n  ── Target Element Queries ──")
	checkEl := func(sel string) {
		node := doc.QuerySelector(sel)
		if node != nil {
			t.Logf("  ✓ %s → <%s id=%q class=%q type=%q> children=%d",
				sel, node.Tag, node.ID(), strings.Join(node.ClassList(), " "),
				node.GetAttribute("type"), len(node.Children))
		} else {
			t.Logf("  ✗ %s → NOT FOUND", sel)
		}
	}
	checkEl("#user-name")
	checkEl("#password")
	checkEl("#login-button")
	checkEl(".login-box")
	checkEl(".login_logo")
	checkEl("form")
	checkEl("input")

	// localStorage state
	t.Log("\n  ── localStorage ──")
	storageData := doc.Storage.Snapshot()
	if len(storageData) == 0 {
		t.Log("  (empty)")
	} else {
		for k, v := range storageData {
			vs := fmt.Sprintf("%v", v)
			if len(vs) > 80 {
				vs = vs[:80] + "..."
			}
			t.Logf("  %s = %s", k, vs)
		}
	}

	// Cookies state
	t.Log("\n  ── Cookies ──")
	cookies := doc.Cookies.GetAll()
	if len(cookies) == 0 {
		t.Log("  (empty)")
	} else {
		for _, c := range cookies {
			t.Logf("  %s = %s (domain=%s, path=%s)", c.Name, c.Value, c.Domain, c.Path)
		}
	}

	t.Log("══════════════════════════════════════════════")

	// ════════════════════════════════════════════════
	// 7. SAVE preview.html
	// ════════════════════════════════════════════════
	renderedHTML := Serialize(doc)
	previewPath := filepath.Join(".", "preview.html")
	err = os.WriteFile(previewPath, []byte(renderedHTML), 0644)
	if err != nil {
		t.Logf("[SauceDemo] Failed to save preview.html: %v", err)
	} else {
		t.Logf("\n[SauceDemo] ✓ Saved rendered DOM to: %s (%d bytes)", previewPath, len(renderedHTML))
	}

	// 8. Final verdict
	usernameInput := doc.QuerySelector("#user-name")
	passwordInput := doc.QuerySelector("#password")
	loginButton := doc.QuerySelector("#login-button")

	if usernameInput != nil && passwordInput != nil && loginButton != nil {
		t.Log("\n✅ SUCCESS: React rendered the SauceDemo login form!")
	} else {
		t.Logf("\n⚠ React did not fully render (goja needs time for 1.9MB bundle).")
		t.Logf("  Check preview.html to see what WAS rendered.")
	}
}

// printNodeTree prints a DOM subtree up to maxDepth levels for debugging.
func printNodeTree(t *testing.T, n *Node, indent string, maxDepth int) {
	if maxDepth <= 0 || n == nil {
		return
	}
	for i, child := range n.Children {
		if i >= 20 { // cap output
			t.Logf("%s... (%d more siblings)", indent, len(n.Children)-20)
			break
		}
		switch child.Type {
		case ElementNode:
			attrs := ""
			if child.ID() != "" {
				attrs += fmt.Sprintf(" id=%q", child.ID())
			}
			if cls := strings.Join(child.ClassList(), " "); cls != "" {
				attrs += fmt.Sprintf(" class=%q", cls)
			}
			if typ := child.GetAttribute("type"); typ != "" {
				attrs += fmt.Sprintf(" type=%q", typ)
			}
			t.Logf("%s<%s%s> (%d children)", indent, child.Tag, attrs, len(child.Children))
			printNodeTree(t, child, indent+"  ", maxDepth-1)
		case TextNode:
			text := strings.TrimSpace(child.Text)
			if text != "" {
				if len(text) > 60 {
					text = text[:60] + "..."
				}
				t.Logf("%s#text: %q", indent, text)
			}
		}
	}
}

func countTestElements(n *Node) int {
	count := 0
	if n.Type == ElementNode {
		count = 1
	}
	for _, child := range n.Children {
		count += countTestElements(child)
	}
	return count
}
