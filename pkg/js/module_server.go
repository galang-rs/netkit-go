package js

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/dop251/goja"
)

type JSHTTPServer struct {
	runtime     *Runtime
	engine      engine.Engine
	routes      map[string][]routeHandler
	middlewares []goja.Callable
	mu          sync.RWMutex
}

type routeHandler struct {
	method  string
	path    string
	handler goja.Callable
}

func RegisterHTTPServerModule(r *Runtime, jsCtx map[string]interface{}, eng engine.Engine) {
	s := &JSHTTPServer{
		runtime: r,
		engine:  eng,
		routes:  make(map[string][]routeHandler),
	}

	jsCtx["http"] = map[string]interface{}{
		"createServer": func() map[string]interface{} {
			return map[string]interface{}{
				"use": func(handler goja.Callable) {
					s.mu.Lock()
					defer s.mu.Unlock()
					s.middlewares = append(s.middlewares, handler)
				},
				"get": func(path string, handler goja.Callable) {
					s.addRoute("GET", path, handler)
				},
				"post": func(path string, handler goja.Callable) {
					s.addRoute("POST", path, handler)
				},
				"put": func(path string, handler goja.Callable) {
					s.addRoute("PUT", path, handler)
				},
				"delete": func(path string, handler goja.Callable) {
					s.addRoute("DELETE", path, handler)
				},
				"listen": func(port int) {
					go s.Listen(port)
				},
			}
		},
	}
}

func (s *JSHTTPServer) addRoute(method, path string, handler goja.Callable) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[method] = append(s.routes[method], routeHandler{
		method:  method,
		path:    path,
		handler: handler,
	})
}

func (s *JSHTTPServer) Listen(port int) {
	addr := fmt.Sprintf(":%d", port)
	http.ListenAndServe(addr, s)
}

func (s *JSHTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Add Powered-By header
	w.Header().Set("X-Powered-By", "NetKit")

	req := map[string]interface{}{
		"method":  r.Method,
		"url":     r.URL.String(),
		"path":    r.URL.Path,
		"headers": r.Header,
	}

	// Trigger OnConnect hook for JS (each HTTP request is a logical "connection" event for the server)
	if s.engine != nil {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		cfg := s.engine.OnConnect(&engine.ConnInfo{
			Type:    "js_http_server",
			Source:  r.RemoteAddr,
			Dest:    r.Host,
			IP:      host,
			Through: "direct",
			Path:    r.URL.Path,
		})
		if cfg != nil && strings.ToLower(cfg.Type) == "drop" {
			// Hijack and close manually to simulate a TCP drop
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				if conn != nil {
					conn.Close()
				}
			}
			return
		}
	}

	body, _ := io.ReadAll(r.Body)
	s.runtime.Lock()
	defer s.runtime.Unlock()

	req["body"] = body
	req["bodyString"] = string(body)

	// Create the JS response object as a map for Express-like compatibility (lowercase methods + chaining)
	var jsRes map[string]interface{}
	statusCode := 200
	headerWritten := false

	writeHeader := func() {
		if !headerWritten {
			w.WriteHeader(statusCode)
			headerWritten = true
		}
	}

	jsRes = map[string]interface{}{
		"status": func(code int) map[string]interface{} {
			statusCode = code
			return jsRes
		},
		"json": func(data interface{}) {
			w.Header().Set("Content-Type", "application/json")
			writeHeader()
			b, _ := json.Marshal(data)
			_, _ = w.Write(b)
		},
		"send": func(data interface{}) {
			writeHeader()
			if b, ok := data.([]byte); ok {
				_, _ = w.Write(b)
			} else {
				_, _ = w.Write([]byte(fmt.Sprint(data)))
			}
		},
		"setHeader": func(key, value string) map[string]interface{} {
			w.Header().Set(key, value)
			return jsRes
		},
	}

	// Execute middlewares
	for _, mw := range s.middlewares {
		nextCalled := false
		next := func() {
			nextCalled = true
		}
		_, err := mw(goja.Undefined(), s.runtime.vm.ToValue(req), s.runtime.vm.ToValue(jsRes), s.runtime.vm.ToValue(next))
		if err != nil {
			fmt.Printf("[HTTPServer Error] Middleware: %v\n", err)
			return
		}
		if !nextCalled {
			return
		}
	}

	// Route matching
	s.mu.RLock()
	routes := s.routes[r.Method]
	s.mu.RUnlock()

	for _, rt := range routes {
		if rt.path == r.URL.Path {
			_, err := rt.handler(goja.Undefined(), s.runtime.vm.ToValue(req), s.runtime.vm.ToValue(jsRes))
			if err != nil {
				fmt.Printf("[HTTPServer Error] Handler: %v\n", err)
				statusCode = 500
				writeHeader()
				_, _ = w.Write([]byte(err.Error()))
			}
			writeHeader() // Ensure headers sent if handler did nothing
			return
		}
	}

	statusCode = 404
	writeHeader()
	_, _ = w.Write([]byte("Not Found"))
}
