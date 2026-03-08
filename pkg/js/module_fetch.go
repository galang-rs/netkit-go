package js

import (
	"fmt"
	"strings"
	"time"

	"http-interperation/pkg/browser"
	"http-interperation/pkg/sandbox"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/dop251/goja"
)

// RegisterFetchModule injects the global `fetch` function into the VM.
// Now powered by http-interperation for premium TLS/Fingerprinting.
func RegisterFetchModule(r *Runtime) {
	vm := r.vm
	vm.Set("fetch", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return vm.ToValue(map[string]interface{}{
				"error": "fetch requires a URL argument",
			})
		}

		rawURL := call.Arguments[0].String()

		// Default options
		method := "GET"
		bodyStr := ""
		headers := map[string]string{}
		profileName := ""

		// Parse options (second argument)
		if len(call.Arguments) > 1 {
			opts := call.Arguments[1].Export()
			if optsMap, ok := opts.(map[string]interface{}); ok {
				if m, ok := optsMap["method"].(string); ok {
					method = strings.ToUpper(m)
				}
				if b, ok := optsMap["body"].(string); ok {
					bodyStr = b
				}
				if h, ok := optsMap["headers"].(map[string]interface{}); ok {
					for k, v := range h {
						headers[k] = fmt.Sprintf("%v", v)
					}
				}
				if p, ok := optsMap["profile"].(string); ok {
					profileName = p
				}
			}
		}

		// Use http-interperation to execute
		profile, err := browser.GenerateFromProfile(profileName)
		if err != nil {
			return vm.ToValue(map[string]interface{}{
				"error": fmt.Sprintf("failed to generate profile: %v", err),
				"ok":    false,
			})
		}

		r.Unlock()
		resp, err := sandbox.Fetch(profile, method, rawURL, headers, bodyStr, "", nil)
		r.Lock()
		if err != nil {
			return vm.ToValue(map[string]interface{}{
				"error":  fmt.Sprintf("request failed: %v", err),
				"status": 0,
				"ok":     false,
			})
		}

		// Build response headers map
		respHeaders := make(map[string]interface{})
		for k, v := range resp.Header() {
			if len(v) == 1 {
				respHeaders[k] = v[0]
			} else {
				respHeaders[k] = v
			}
		}

		result := map[string]interface{}{
			"status":     resp.Status(),
			"statusText": fmt.Sprintf("%d %s", resp.Status(), ""),
			"headers":    respHeaders,
			"body":       string(resp.Bytes()),
			"bodyBytes":  resp.Bytes(),
			"url":        rawURL,
			"ok":         resp.Status() >= 200 && resp.Status() < 300,
		}

		promise, resolve, _ := vm.NewPromise()
		resolve(vm.ToValue(result))
		return vm.ToValue(promise)
	})
}

// RegisterAsyncFetch injects the ctx.FetchAsync method that callbacks to onPacket.
func RegisterAsyncFetch(jsCtx map[string]interface{}, eng engine.Engine, pkt *engine.Packet) {
	jsCtx["FetchAsync"] = func(rawURL string, options ...map[string]interface{}) {
		// Get current reference
		var ref string
		if pkt.Metadata != nil {
			if r, ok := pkt.Metadata["Reference"].(string); ok {
				ref = r
			}
		}

		// Parse options
		method := "GET"
		bodyStr := ""
		headers := map[string]string{}
		profileName := ""

		if len(options) > 0 {
			opts := options[0]
			if m, ok := opts["method"].(string); ok {
				method = strings.ToUpper(m)
			}
			if b, ok := opts["body"].(string); ok {
				bodyStr = b
			}
			if h, ok := opts["headers"].(map[string]interface{}); ok {
				for k, v := range h {
					headers[k] = fmt.Sprintf("%v", v)
				}
			}
			if p, ok := opts["profile"].(string); ok {
				profileName = p
			}
			// Manual reference override if provided
			if r, ok := opts["reference"].(string); ok {
				ref = r
			}
		}

		go func() {
			profile, err := browser.GenerateFromProfile(profileName)
			if err != nil {
				return
			}

			resp, err := sandbox.Fetch(profile, method, rawURL, headers, bodyStr, "", nil)
			if err != nil {
				return
			}

			// Capture response headers
			respHeaders := make(map[string]interface{})
			for k, v := range resp.Header() {
				if len(v) == 1 {
					respHeaders[k] = v[0]
				} else {
					respHeaders[k] = v
				}
			}

			// Ingest synthetic packet back into engine
			respPkt := &engine.Packet{
				ID:        uint64(time.Now().UnixNano()),
				Timestamp: time.Now().Unix(),
				Source:    "fetch-async",
				Protocol:  "HTTP-ASYNC",
				Payload:   resp.Bytes(),
				Metadata: map[string]interface{}{
					"IsFetchResponse": true,
					"Reference":       ref,
					"Status":          resp.Status(),
					"Headers":         respHeaders,
					"URL":             rawURL,
				},
			}
			eng.Ingest(respPkt)
		}()
	}
}
