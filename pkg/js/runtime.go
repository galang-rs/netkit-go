package js

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bacot120211/netkit-go/pkg/adblock"
	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/protocol/tls"
	"github.com/bacot120211/netkit-go/pkg/security"
	"github.com/google/uuid"

	"github.com/dop251/goja"
)

// Runtime handles the execution of JS scripts
type Runtime struct {
	vm          *goja.Runtime
	mu          sync.Mutex
	require     *RequireManager
	baseModules map[string]interface{}
	OnDomain    func(domain string)
	OnReset     func()
	OnExit      func()
	ShouldMITM  func(string) bool

	// Security components
	Firewall *security.Firewall
	Scope    *security.ScopeManager
	Limiter  *security.BruteforceLimiter
}

func NewRuntime() (*Runtime, error) {
	vm := goja.New()
	r := &Runtime{
		vm:          vm,
		baseModules: make(map[string]interface{}),
	}
	r.initializeBaseModules(nil, nil)
	return r, nil
}

func (r *Runtime) Lock() {
	r.mu.Lock()
}

func (r *Runtime) Unlock() {
	r.mu.Unlock()
}

func (r *Runtime) Initialize(eng engine.Engine, ca *tls.CA, fw *security.Firewall, sm *security.ScopeManager, bl *security.BruteforceLimiter) {
	r.Lock()
	defer r.Unlock()
	r.Firewall = fw
	r.Scope = sm
	r.Limiter = bl
	// Re-initialize with real engine/CA and security
	r.initializeBaseModules(eng, ca)
}

func (r *Runtime) initializeBaseModules(eng engine.Engine, ca *tls.CA) {
	RegisterConsole(r)
	RegisterTimers(r)
	RegisterFetchModule(r)
	m := r.baseModules
	RegisterFSModule(m, nil)
	RegisterMIMEModule(m)
	RegisterDNSModule(m)
	RegisterNetModule(r, m)
	RegisterWebSocketModule(r, m)
	RegisterHTTPServerModule(r, m, eng)
	RegisterHTTPModule(m)
	RegisterTLSModule(r, m, eng)
	RegisterStackModule(r, m)
	RegisterCryptoModule(m)
	RegisterProtobufModule(m)
	RegisterProxyModule(r, r.baseModules, eng, ca, r.ShouldMITM)
	RegisterTrafficModule(m)
	RegisterMetricsModule(m)
	RegisterSyncModule(m)
	RegisterTestSimModule(m)
	RegisterSQLiteModule(m)
	RegisterSecurityModule(m, r.Firewall, r.Scope, r.Limiter)
	RegisterIDSModule(m)
	RegisterMemModule(m)
	RegisterCLIModule(r, m)
	RegisterTunnelModule(r, m, eng, ca)
	RegisterNodeModule(r, m)

	// Inject base modules into global scope
	for k, v := range r.baseModules {
		r.vm.Set(k, v)
	}

	// Register global helper functions
	r.vm.Set("Reset", func() {
		if r.OnReset != nil {
			r.OnReset()
		}
	})
	r.vm.Set("Exit", func() {
		if r.OnExit != nil {
			r.OnExit()
		}
	})
	r.vm.Set("Domain", func(domain string) {
		if r.OnDomain != nil {
			r.OnDomain(domain)
		}
	})

	// Inject aliases
	r.vm.Set("net", m["Net"])
	r.vm.Set("http", m["http"])
}

// LoadScript loads and runs a JS file into the runtime.
func (r *Runtime) LoadScript(path string) error {
	r.Lock()
	defer r.Unlock()
	return r.loadScript(path)
}

func (r *Runtime) loadScript(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Initialize RequireManager with the script's directory as base
	r.require = NewRequireManager(r.vm, filepath.Dir(path))

	// Expose require to global scope
	r.vm.Set("require", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			panic(r.vm.ToValue("require() requires 1 argument"))
		}
		p := call.Arguments[0].String()
		res, err := r.require.Require(p)
		if err != nil {
			panic(r.vm.ToValue(logger.Errorf("require error: %v", err)))
		}
		return res
	})

	_, err = r.vm.RunString(string(content))
	return err
}

// AccountSaver is implemented by the account manager bridge to allow JS to persist data.
type AccountSaver interface {
	SaveTLS(ja3, ja4, ja3s, ja4s, akamai, cloudflare string)
	SaveCookie(name, value string)
	SaveToken(token string)
	SaveUA(ua string)
	ComputeClientHello(payload []byte)
	ComputeServerHello(payload []byte)
}

// JSInterceptor is an engine.Interceptor that calls into JS
type JSInterceptor struct {
	runtime           *Runtime
	handler           goja.Callable
	onConnectHandler  goja.Callable // optional: 'onConnect' function
	onErrorHandler    goja.Callable // optional: 'onError' function
	onRequestHandler  goja.Callable // optional: 'onRequest' function
	onResponseHandler goja.Callable // optional: 'onResponse' function
	onAdsHandler      goja.Callable // optional: 'onAds' function
	name              string
	engine            engine.Engine
	account           AccountSaver // optional: if set, exposes ctx.Account to JS
}

func NewJSInterceptor(r *Runtime, scriptPath string, eng engine.Engine, ca *tls.CA, shouldMITM func(string) bool) (*JSInterceptor, error) {
	r.Lock()
	defer r.Unlock()

	r.ShouldMITM = shouldMITM
	if err := r.loadScript(scriptPath); err != nil {
		return nil, err
	}

	// Expecting a global function 'onPacket' in the JS script
	val := r.vm.Get("onPacket")
	handler, _ := goja.AssertFunction(val) // can be nil if only onConnect is used

	// Optional 'onConnect' function
	connVal := r.vm.Get("onConnect")
	onConnectHandler, _ := goja.AssertFunction(connVal)

	// Optional specialized hooks
	errVal := r.vm.Get("onError")
	onErrorHandler, _ := goja.AssertFunction(errVal)

	reqVal := r.vm.Get("onRequest")
	onRequestHandler, _ := goja.AssertFunction(reqVal)

	respVal := r.vm.Get("onResponse")
	onResponseHandler, _ := goja.AssertFunction(respVal)

	adsVal := r.vm.Get("onAds")
	onAdsHandler, _ := goja.AssertFunction(adsVal)

	// Optional 'init' function
	initVal := r.vm.Get("init")
	initHandler, _ := goja.AssertFunction(initVal)

	if handler == nil && onConnectHandler == nil && onRequestHandler == nil && onResponseHandler == nil && onAdsHandler == nil && onErrorHandler == nil && initHandler == nil {
		return nil, logger.Errorf("no JS handlers (init, onPacket, onConnect, onRequest, onResponse, onAds, onError) found in script")
	}

	RegisterScriptModule(r, map[string]interface{}{})
	RegisterProxyModule(r, r.baseModules, eng, ca, r.ShouldMITM)
	r.vm.Set("Proxy", r.baseModules["Proxy"])
	RegisterTLSModule(r, r.baseModules, eng)
	RegisterTunnelModule(r, r.baseModules, eng, ca)
	r.vm.Set("Tunnel", r.baseModules["Tunnel"])
	RegisterConnectModule(r, r.baseModules) // Ensure connect is available
	r.vm.Set("connect", r.baseModules["connect"])

	interceptor := &JSInterceptor{
		runtime:           r,
		handler:           handler,
		onConnectHandler:  onConnectHandler,
		onErrorHandler:    onErrorHandler,
		onRequestHandler:  onRequestHandler,
		onResponseHandler: onResponseHandler,
		onAdsHandler:      onAdsHandler,
		name:              scriptPath,
		engine:            eng,
	}

	// Helper to resolve a handler from a value (string name or boolean false to disable)
	getHandler := func(val interface{}) goja.Callable {
		if b, ok := val.(bool); ok && !b {
			return nil
		}
		if s, ok := val.(string); ok {
			v := r.vm.Get(s)
			if fn, ok := goja.AssertFunction(v); ok {
				return fn
			}
		}
		return nil
	}

	// Register global 'setFunc' to allow dynamic control over JS hooks
	r.vm.Set("setFunc", func(opts map[string]interface{}) {
		for k, v := range opts {
			switch k {
			case "onPacket":
				interceptor.handler = getHandler(v)
			case "onConnect":
				interceptor.onConnectHandler = getHandler(v)
			case "onError":
				interceptor.onErrorHandler = getHandler(v)
			case "onRequest":
				interceptor.onRequestHandler = getHandler(v)
			case "onResponse":
				interceptor.onResponseHandler = getHandler(v)
			case "onAds":
				interceptor.onAdsHandler = getHandler(v)
			}
		}
	})

	// Wire up runtime callbacks
	r.OnReset = func() {
		initVal := r.vm.Get("init")
		if initFn, ok := goja.AssertFunction(initVal); ok {
			_, _ = initFn(goja.Undefined())
		}
	}
	r.OnExit = func() {
		closeVal := r.vm.Get("closing")
		if closeFn, ok := goja.AssertFunction(closeVal); ok {
			_, _ = closeFn(goja.Undefined())
		}
		os.Exit(0)
	}

	r.OnDomain = func(domain string) {
		if j, ok := eng.(interface{ RegisterDomain(string) }); ok {
			j.RegisterDomain(domain)
		}
	}

	// Call optional 'init' function if it exists
	if initHandler != nil {
		_, err := initHandler(goja.Undefined())
		if err != nil {
			return nil, logger.Errorf("init error: %v", err)
		}
	}

	return interceptor, nil
}

func (j *JSInterceptor) OnConnect(info *engine.ConnInfo) *engine.TunnelConfig {
	if j.onConnectHandler == nil {
		return nil
	}

	j.runtime.Lock()
	defer j.runtime.Unlock()

	isDropped := false
	// Call onConnect(info)
	jsInfo := map[string]interface{}{
		"Type":       info.Type,
		"Source":     info.Source,
		"Dest":       info.Dest,
		"IP":         info.IP,
		"Through":    info.Through,
		"RemoteAddr": info.Source,  // Helper alias
		"LocalAddr":  info.IP,      // Helper alias (IP of the listener/interface)
		"LocalHost":  info.Through, // Helper alias (IP type or interface name)
		"Path":       info.Path,    // Full HTTP path
		"Drop": func() {
			isDropped = true
		},
	}
	val, err := j.onConnectHandler(goja.Undefined(), j.runtime.vm.ToValue(jsInfo))
	if err != nil {
		logger.Printf("[JS OnConnect Error] %v\n", err)
		return nil
	}

	if isDropped {
		return &engine.TunnelConfig{Type: "drop"}
	}

	// Result should be a connect object (map with Type, URL, WGConfig)
	if val == nil || goja.IsUndefined(val) || goja.IsNull(val) {
		return nil
	}

	export := val.Export()

	// Case 1: Direct TunnelConfig struct (returned by connect.wg() / connect.proxy() / connect.ssh())
	if tc, ok := export.(*engine.TunnelConfig); ok {
		if tc.Type != "" {
			logger.Printf("[JS OnConnect] ✅ Tunnel config (direct): Type=%s\n", tc.Type)
			return tc
		}
	}

	// Case 2: Plain JS object (map)
	if cfgMap, ok := export.(map[string]interface{}); ok {
		tc := &engine.TunnelConfig{}
		if t, ok := cfgMap["Type"].(string); ok {
			tc.Type = t
		} else if t, ok := cfgMap["type"].(string); ok {
			tc.Type = t
		}

		if u, ok := cfgMap["URL"].(string); ok {
			tc.URL = u
		} else if u, ok := cfgMap["url"].(string); ok {
			tc.URL = u
		}

		if w, ok := cfgMap["WGConfig"].(string); ok {
			tc.WGConfig = w
		} else if w, ok := cfgMap["wg_config"].(string); ok {
			tc.WGConfig = w
		} else if w, ok := cfgMap["conf"].(string); ok {
			tc.WGConfig = w
		}

		if tc.Type != "" {
			logger.Printf("[JS OnConnect] ✅ Tunnel config (map): Type=%s\n", tc.Type)
			return tc
		}
	}

	logger.Printf("[JS OnConnect] ⚠️  onConnect returned value but could not parse as TunnelConfig (type: %T)\n", export)
	return nil
}

func (j *JSInterceptor) Close() error {
	j.runtime.Lock()
	defer j.runtime.Unlock()

	// Call optional 'closing' function if it exists
	if closeFn, ok := goja.AssertFunction(j.runtime.vm.Get("closing")); ok {
		_, err := closeFn(goja.Undefined())
		if err != nil {
			return logger.Errorf("closing error: %v", err)
		}
	}
	return nil
}

// SetAccountSaver attaches an AccountSaver so JS ctx.Account callbacks work.
func (j *JSInterceptor) SetAccountSaver(a AccountSaver) {
	j.account = a
}

func (j *JSInterceptor) Name() string {
	return j.name
}

func (j *JSInterceptor) OnPacket(ctx *engine.PacketContext) error {
	j.runtime.Lock()
	defer j.runtime.Unlock()

	vm := j.runtime.vm
	handler := j.handler

	// Build the JS context object starting with base modules
	jsCtx := make(map[string]interface{}, len(j.runtime.baseModules)+10)
	for k, v := range j.runtime.baseModules {
		jsCtx[k] = v
	}

	// Add/Override per-packet context
	jsCtx["Packet"] = ctx.Packet
	if ctx.Conn != nil {
		jsCtx["Conn"] = ctx.Conn
	}
	jsCtx["Reference"] = func(val ...string) string {
		if len(val) > 0 {
			if ctx.Packet.Metadata == nil {
				ctx.Packet.Metadata = make(map[string]interface{})
			}
			ctx.Packet.Metadata["Reference"] = val[0]
			if ctx.Session != nil {
				ctx.Session.Data.Store("current_ref", val[0])
			}
			return val[0]
		}
		
		if ctx.Packet.Metadata != nil {
			if ref, ok := ctx.Packet.Metadata["Reference"].(string); ok && ref != "" {
				return ref
			}
		}

		// Try Flow module's refID (based on last_http_req_id) to align
		// ctx.Reference() with ctx.Flow.Reference() for HTTP correlation.
		if flow, ok := jsCtx["Flow"].(map[string]interface{}); ok {
			if refFn, ok := flow["Reference"].(func() interface{}); ok {
				if flowRef := refFn(); flowRef != nil {
					ref := fmt.Sprintf("%v", flowRef)
					if ctx.Packet.Metadata == nil {
						ctx.Packet.Metadata = make(map[string]interface{})
					}
					ctx.Packet.Metadata["Reference"] = ref
					if ctx.Session != nil {
						ctx.Session.Data.Store("current_ref", ref)
					}
					return ref
				}
			}
		}

		if ctx.Session != nil {
			if refVal, ok := ctx.Session.Data.Load("current_ref"); ok {
				ref := refVal.(string)
				if ctx.Packet.Metadata == nil {
					ctx.Packet.Metadata = make(map[string]interface{})
				}
				ctx.Packet.Metadata["Reference"] = ref
				return ref
			}
		}

		ref := uuid.New().String()
		if ctx.Packet.Metadata == nil {
			ctx.Packet.Metadata = make(map[string]interface{})
		}
		ctx.Packet.Metadata["Reference"] = ref
		if ctx.Session != nil {
			ctx.Session.Data.Store("current_ref", ref)
		}
		return ref
	}
	jsCtx["Drop"] = func() {
		ctx.Action = engine.ActionDrop
	}
	jsCtx["Modify"] = func(payload interface{}) {
		ctx.Packet.Payload = gojaToBytes(payload)
		ctx.Action = engine.ActionModified
	}
	jsCtx["Bypass"] = func() {
		ctx.Action = engine.ActionBypass
	}
	jsCtx["Respond"] = func(payload interface{}) {
		if ctx.Responder != nil {
			data := gojaToBytes(payload)
			if data != nil {
				_ = ctx.Responder(data)
			}
		}
	}
	jsCtx["Send"] = func(payload interface{}, opts map[string]interface{}) {
		data := gojaToBytes(payload)
		if data == nil {
			return
		}
		p := &engine.Packet{
			ID: engine.NextPacketID(), Timestamp: time.Now().Unix(),
			Source: ctx.Packet.Source, SourcePort: ctx.Packet.SourcePort,
			Dest: ctx.Packet.Dest, DestPort: ctx.Packet.DestPort,
			Protocol: ctx.Packet.Protocol, Payload: data,
		}
		if opts != nil {
			if src, ok := opts["source"].(string); ok {
				p.Source = src
			}
			if sp, ok := opts["srcPort"].(int64); ok {
				p.SourcePort = uint16(sp)
			}
			if dst, ok := opts["dest"].(string); ok {
				p.Dest = dst
			}
			if dp, ok := opts["dstPort"].(int64); ok {
				p.DestPort = uint16(dp)
			}
			if proto, ok := opts["protocol"].(string); ok {
				p.Protocol = proto
			}
		}
		j.engine.Ingest(p)
	}
	jsCtx["Recv"] = func(payload interface{}) {
		data := gojaToBytes(payload)
		if data != nil {
			ctx.Packet.Payload = data
			ctx.Action = engine.ActionModified
		}
	}
	jsCtx["SetPriority"] = func(priority int) {
		ctx.Priority = priority
	}

	// Add dynamic modules that depend on current packet
	RegisterSessionModule(jsCtx, ctx.Session)
	RegisterFlowModule(jsCtx, ctx)
	RegisterAsyncDNS(jsCtx, j.engine, ctx.Packet)
	RegisterAsyncFetch(jsCtx, j.engine, ctx.Packet)
	RegisterMirrorModule(jsCtx, ctx.Packet, j.engine)
	RegisterConnectModule(j.runtime, jsCtx)
	RegisterCGNATModule(j.runtime, jsCtx)

	// Add FullURL to ctx (alias for Flow.FullURL)
	fullURL := ""
	hostname := ""
	if flow, ok := jsCtx["Flow"].(map[string]interface{}); ok {
		if val, ok := flow["FullURL"].(string); ok {
			fullURL = val
			jsCtx["FullURL"] = val
		}
		// Try to get hostname from packet metadata or flow
		if h, ok := ctx.Packet.Metadata["Hostname"].(string); ok {
			hostname = h
		} else if h, ok := ctx.Packet.Metadata["hostname"].(string); ok {
			hostname = h
		}
	}

	// Engine-level Ad Detection
	if fullURL != "" {
		if res, ok := adblock.GetEngine().Match(fullURL, hostname); ok {
			ctx.AdResult = res
			jsCtx["Ad"] = res
		} else {
			// Provide empty Ad object instead of nil for safety
			jsCtx["Ad"] = &adblock.Result{IsAd: false}
		}
	}

	if j.account != nil {
		RegisterTLSAccountModule(jsCtx, j.account)
	}

	// Helper to call a JS function with error mapping to onError
	callJS := func(fn goja.Callable, ctx interface{}) error {
		defer func() {
			if r := recover(); r != nil {
				errStr := fmt.Sprintf("%v", r)
				if j.onErrorHandler != nil {
					_, _ = j.onErrorHandler(goja.Undefined(), vm.ToValue(errStr))
				} else {
					logger.Printf("[JS PANIC] %v\n", r)
				}
			}
		}()

		_, err := fn(goja.Undefined(), vm.ToValue(ctx))
		if err != nil {
			if j.onErrorHandler != nil {
				_, _ = j.onErrorHandler(goja.Undefined(), vm.ToValue(err.Error()))
			} else {
				logger.Printf("[JS ERROR] %v\n", err)
			}
			return err
		}
		return nil
	}

	flowModule := jsCtx["Flow"].(map[string]interface{})
	isFlowReq := flowModule["IsHTTPRequest"].(func() bool)()
	isFlowResp := flowModule["IsHTTPResponse"].(func() bool)()

	// Trigger onAds if it targets HTTP traffic
	if j.onAdsHandler != nil && (isFlowReq || isFlowResp) {
		_ = callJS(j.onAdsHandler, jsCtx)
	}

	// Branching: onRequest / onResponse / onPacket
	if isFlowReq && j.onRequestHandler != nil {
		_ = callJS(j.onRequestHandler, jsCtx)
	} else if isFlowResp && j.onResponseHandler != nil {
		_ = callJS(j.onResponseHandler, jsCtx)
	} else if handler != nil {
		_ = callJS(handler, jsCtx)
	}

	// Post-execution: Sync Connect config back to session
	if connVal, ok := jsCtx["Connect"]; ok && connVal != nil {
		if cfg, ok := connVal.(*engine.TunnelConfig); ok {
			ctx.Session.Tunnel = cfg
		} else if cfgMap, ok := connVal.(map[string]interface{}); ok {
			// If JS returned a plain object, try to parse it
			tc := &engine.TunnelConfig{}
			if t, ok := cfgMap["type"].(string); ok {
				tc.Type = t
			}
			if u, ok := cfgMap["url"].(string); ok {
				tc.URL = u
			}
			if w, ok := cfgMap["conf"].(string); ok {
				tc.WGConfig = w
			}
			if tc.Type != "" {
				ctx.Session.Tunnel = tc
			}
		}
	}

	// Record history if someone called Snapshot or just for tracking
	if flow, ok := jsCtx["Flow"].(map[string]interface{}); ok {
		if snapFn, ok := flow["Snapshot"].(func() map[string]interface{}); ok {
			RegisterHistory(snapFn())
		}
	}

	return nil
}
