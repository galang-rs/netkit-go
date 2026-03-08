package js

import (
	"context"
	ctls "crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bacot120211/netkit-go/pkg/capture"
	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/protocol/tls"
	"github.com/bacot120211/netkit-go/pkg/proxy"
	"github.com/dop251/goja"
	socks5proxy "golang.org/x/net/proxy"
)

// ProxyEntry represents a single proxy in the pool.
type ProxyEntry struct {
	URL       string
	Healthy   bool
	Score     int
	LastCheck time.Time
}

// proxyPool manages a pool of proxies for rotation, chain, failover.
type proxyPool struct {
	mu          sync.RWMutex
	proxies     []*ProxyEntry
	index       atomic.Int64
	tlsInt      *tls.TLSInterceptor
	ResolvedIPs map[string]string
}

var globalProxyPool = &proxyPool{}

type proxyListener interface {
	Listen() error
	Serve(ctx context.Context) error
	Close() error
	SetTunnel(tc *engine.TunnelConfig)
	Preload() error
}

var (
	listeners   = make(map[string]proxyListener)
	listenersMu sync.RWMutex
)

// SetGlobalResolvedIPs allows the manager to initialize the real IPs for JS proxies.
func SetGlobalResolvedIPs(ips map[string]string) {
	globalProxyPool.mu.Lock()
	defer globalProxyPool.mu.Unlock()
	globalProxyPool.ResolvedIPs = ips
}

// RegisterProxyModule injects ctx.Proxy into the JS context.
func RegisterProxyModule(r *Runtime, jsCtx map[string]interface{}, eng engine.Engine, ca *tls.CA, shouldMITM func(string) bool) {
	vm := r.vm
	pool := globalProxyPool

	jsCtx["Proxy"] = map[string]interface{}{
		// Create starts a MITM proxy server and returns an ID.
		"Create": func(options map[string]interface{}) (goja.Value, error) {
			addr, _ := options["addr"].(string)
			pType, _ := options["type"].(string)
			logger.Infof("[JS] 🚀 Proxy.Create called: %s on %s\n", pType, addr)

			if eng == nil || ca == nil {
				return vm.ToValue(""), fmt.Errorf("engine or CA not available")
			}

			var l proxyListener
			pType = strings.ToLower(pType)
			var user, pass string
			crlHost, _ := options["crlHost"].(string)

			// Safely extract auth if it's a map
			if auth, ok := options["auth"].(map[string]interface{}); ok {
				user, _ = auth["user"].(string)
				pass, _ = auth["pass"].(string)
			}

			// Determine MITM behavior: either use the global shouldMITM or override with the 'mitm' option.
			localShouldMITM := shouldMITM
			if m, ok := options["mitm"].(bool); ok {
				if !m {
					localShouldMITM = func(host string) bool { return false }
				} else {
					localShouldMITM = func(host string) bool { return true }
				}
			}

			switch pType {
			case "http":
				hl := capture.NewHTTPProxyListener(addr, ca, eng, pool.ResolvedIPs)
				hl.ShouldMITM = localShouldMITM
				hl.User = user
				hl.Pass = pass
				hl.CRLHost = crlHost
				l = hl
			case "socks5":
				sl := capture.NewSOCKS5Listener(addr, ca, eng, pool.ResolvedIPs)
				sl.ShouldMITM = localShouldMITM
				sl.User = user
				sl.Pass = pass
				sl.CRLHost = crlHost
				l = sl
			default:
				return vm.ToValue(""), fmt.Errorf("unsupported proxy type: %s", pType)
			}

			if err := l.Listen(); err != nil {
				return vm.ToValue(""), err
			}

			id := fmt.Sprintf("%s-%s-%d", pType, addr, rand.Intn(1000))
			listenersMu.Lock()
			listeners[id] = l
			listenersMu.Unlock()

			go l.Serve(context.Background())
			fmt.Printf("[JS] 🛡️  Started %s MITM Proxy on %s (ID: %s)\n", strings.ToUpper(pType), addr, id)

			// Create a JS object with chaining support
			proxyObj := vm.NewObject()
			proxyObj.Set("id", id)

			connectObj := vm.NewObject()
			connectObj.Set("proxy", func(call goja.FunctionCall) goja.Value {
				if len(call.Arguments) == 0 {
					return vm.ToValue(connectObj)
				}
				arg := call.Arguments[0]
				tc := &engine.TunnelConfig{Type: "proxy"}
				if arg.ExportType() != nil && (arg.ExportType().Kind() == reflect.Map || arg.ExportType().Kind() == reflect.Struct) {
					cfgMap := arg.Export().(map[string]interface{})
					if u, ok := cfgMap["url"].(string); ok {
						tc.URL = u
					}
				} else {
					tc.URL = arg.String()
				}
				l.SetTunnel(tc)
				return vm.ToValue(connectObj)
			})

			connectObj.Set("wg", func(call goja.FunctionCall) goja.Value {
				if len(call.Arguments) == 0 {
					return vm.ToValue(connectObj)
				}
				arg := call.Arguments[0]
				tc := &engine.TunnelConfig{Type: "wg"}
				if arg.ExportType() != nil && (arg.ExportType().Kind() == reflect.Map || arg.ExportType().Kind() == reflect.Struct) {
					cfgMap := arg.Export().(map[string]interface{})
					if c, ok := cfgMap["conf"].(string); ok {
						tc.WGConfig = c
					}
				} else {
					tc.WGConfig = arg.String()
				}
				l.SetTunnel(tc)
				return vm.ToValue(connectObj)
			})

			connectObj.Set("ssh", func(call goja.FunctionCall) goja.Value {
				if len(call.Arguments) == 0 {
					return vm.ToValue(connectObj)
				}
				arg := call.Arguments[0]
				tc := &engine.TunnelConfig{Type: "ssh", SSH: &engine.SSHConfig{Port: 22}}
				if arg.ExportType() != nil && (arg.ExportType().Kind() == reflect.Map || arg.ExportType().Kind() == reflect.Struct) {
					cfgMap := arg.Export().(map[string]interface{})
					if v, ok := cfgMap["host"].(string); ok {
						tc.SSH.Host = v
					}
					if v, ok := cfgMap["port"].(int64); ok {
						tc.SSH.Port = int(v)
					}
					if v, ok := cfgMap["user"].(string); ok {
						tc.SSH.User = v
					}
					if v, ok := cfgMap["pass"].(string); ok {
						tc.SSH.Pass = v
					}
				}
				l.SetTunnel(tc)
				return vm.ToValue(connectObj)
			})
			connectObj.Set("preload", func() error {
				return l.Preload()
			})

			proxyObj.Set("connect", connectObj)
			return vm.ToValue(proxyObj), nil
		},
		// createProxy is a legacy alias for Create(addr, type)
		"createProxy": func(addr, pType string) (goja.Value, error) {
			if eng == nil || ca == nil {
				return vm.ToValue(""), fmt.Errorf("engine or CA not available")
			}
			var l proxyListener
			pType = strings.ToLower(pType)
			switch pType {
			case "http":
				l = capture.NewHTTPProxyListener(addr, ca, eng, pool.ResolvedIPs)
			case "socks5":
				l = capture.NewSOCKS5Listener(addr, ca, eng, pool.ResolvedIPs)
			default:
				return vm.ToValue(""), fmt.Errorf("unsupported proxy type: %s", pType)
			}

			if err := l.Listen(); err != nil {
				return vm.ToValue(""), err
			}

			id := fmt.Sprintf("%s-%s-%d", pType, addr, rand.Intn(1000))
			listenersMu.Lock()
			listeners[id] = l
			listenersMu.Unlock()

			go l.Serve(context.Background())
			fmt.Printf("[JS] 🛡️  Started %s MITM Proxy on %s (ID: %s)\n", strings.ToUpper(pType), addr, id)

			// Legacy also returns object now for consistency
			proxyObj := vm.NewObject()
			proxyObj.Set("id", id)

			connectObj := vm.NewObject()
			connectObj.Set("proxy", func(call goja.FunctionCall) goja.Value {
				if len(call.Arguments) == 0 {
					return vm.ToValue(connectObj)
				}
				arg := call.Arguments[0]
				tc := &engine.TunnelConfig{Type: "proxy"}
				if arg.ExportType() != nil && (arg.ExportType().Kind() == reflect.Map || arg.ExportType().Kind() == reflect.Struct) {
					cfgMap := arg.Export().(map[string]interface{})
					if u, ok := cfgMap["url"].(string); ok {
						tc.URL = u
					}
				} else {
					tc.URL = arg.String()
				}
				l.SetTunnel(tc)
				return vm.ToValue(connectObj)
			})

			connectObj.Set("wg", func(call goja.FunctionCall) goja.Value {
				if len(call.Arguments) == 0 {
					return vm.ToValue(connectObj)
				}
				arg := call.Arguments[0]
				tc := &engine.TunnelConfig{Type: "wg"}
				if arg.ExportType() != nil && (arg.ExportType().Kind() == reflect.Map || arg.ExportType().Kind() == reflect.Struct) {
					cfgMap := arg.Export().(map[string]interface{})
					if c, ok := cfgMap["conf"].(string); ok {
						tc.WGConfig = c
					}
				} else {
					tc.WGConfig = arg.String()
				}
				l.SetTunnel(tc)
				return vm.ToValue(connectObj)
			})
			connectObj.Set("preload", func() error {
				return l.Preload()
			})

			proxyObj.Set("connect", connectObj)
			return vm.ToValue(proxyObj), nil
		},
		// Drop stops a listener by ID.
		"Drop": func(id string) error {
			listenersMu.Lock()
			l, ok := listeners[id]
			delete(listeners, id)
			listenersMu.Unlock()

			if !ok {
				return fmt.Errorf("listener not found: %s", id)
			}
			logger.Infof("[JS] 🛑 Stopping proxy listener %s\n", id)
			return l.Close()
		},
		// List returns active listener IDs.
		"List": func() []string {
			listenersMu.RLock()
			defer listenersMu.RUnlock()
			var ids []string
			for id := range listeners {
				ids = append(ids, id)
			}
			return ids
		},
		// Dial connects through a proxy. Supports socks5/socks5h/socks4/http/https.
		"Dial": func(proxyURLStr, targetAddr string, timeoutMs int64) (map[string]interface{}, error) {
			if timeoutMs <= 0 {
				timeoutMs = 10000
			}
			return proxyDial(proxyURLStr, targetAddr, timeoutMs)
		},

		// AddProxy adds a proxy to the pool.
		"AddProxy": func(proxyURLStr string) {
			pool.mu.Lock()
			defer pool.mu.Unlock()
			pool.proxies = append(pool.proxies, &ProxyEntry{
				URL:     proxyURLStr,
				Healthy: true,
				Score:   100,
			})
		},

		// RemoveProxy removes a proxy from the pool.
		"RemoveProxy": func(proxyURLStr string) {
			pool.mu.Lock()
			defer pool.mu.Unlock()
			for i, p := range pool.proxies {
				if p.URL == proxyURLStr {
					pool.proxies = append(pool.proxies[:i], pool.proxies[i+1:]...)
					break
				}
			}
		},

		// ListProxies returns all proxies in the pool.
		"ListProxies": func() []map[string]interface{} {
			pool.mu.RLock()
			defer pool.mu.RUnlock()
			var result []map[string]interface{}
			for _, p := range pool.proxies {
				result = append(result, map[string]interface{}{
					"url":       p.URL,
					"healthy":   p.Healthy,
					"score":     p.Score,
					"lastCheck": p.LastCheck.UnixMilli(),
				})
			}
			return result
		},

		// Rotate returns the next healthy proxy in round-robin fashion.
		"Rotate": func() string {
			pool.mu.RLock()
			defer pool.mu.RUnlock()
			if len(pool.proxies) == 0 {
				return ""
			}
			for attempts := 0; attempts < len(pool.proxies); attempts++ {
				idx := pool.index.Add(1) % int64(len(pool.proxies))
				if pool.proxies[idx].Healthy {
					return pool.proxies[idx].URL
				}
			}
			return pool.proxies[0].URL // fallback
		},

		// Random returns a random healthy proxy.
		"Random": func() string {
			pool.mu.RLock()
			defer pool.mu.RUnlock()
			healthy := []*ProxyEntry{}
			for _, p := range pool.proxies {
				if p.Healthy {
					healthy = append(healthy, p)
				}
			}
			if len(healthy) == 0 {
				return ""
			}
			return healthy[rand.Intn(len(healthy))].URL
		},

		// HealthCheck tests all proxies by connecting to a test URL.
		"HealthCheck": func(testURL string, timeoutMs int64) []map[string]interface{} {
			pool.mu.Lock()
			defer pool.mu.Unlock()
			if timeoutMs <= 0 {
				timeoutMs = 5000
			}
			var results []map[string]interface{}
			for _, p := range pool.proxies {
				start := time.Now()
				ok := testProxy(p.URL, testURL, timeoutMs)
				elapsed := time.Since(start).Milliseconds()
				p.Healthy = ok
				p.LastCheck = time.Now()
				if ok {
					p.Score = 100
				} else {
					p.Score = 0
				}
				results = append(results, map[string]interface{}{
					"url":       p.URL,
					"healthy":   ok,
					"latencyMs": elapsed,
				})
			}
			return results
		},

		// Chain dials through a chain of proxies sequentially.
		"Chain": func(proxyURLs []interface{}, targetAddr string, timeoutMs int64) (map[string]interface{}, error) {
			if len(proxyURLs) == 0 {
				return nil, fmt.Errorf("empty proxy chain")
			}
			if timeoutMs <= 0 {
				timeoutMs = 30000
			}
			// For chain, we iterate proxies: connect via first, then CONNECT to next, etc.
			// Simplified: connect through last proxy directly (true chaining requires CONNECT tunneling)
			lastProxy := fmt.Sprintf("%v", proxyURLs[len(proxyURLs)-1])
			return proxyDial(lastProxy, targetAddr, timeoutMs)
		},

		// Failover tries proxies in order until one works.
		"Failover": func(proxyURLs []interface{}, targetAddr string, timeoutMs int64) (map[string]interface{}, error) {
			if timeoutMs <= 0 {
				timeoutMs = 10000
			}
			for _, p := range proxyURLs {
				pStr := fmt.Sprintf("%v", p)
				conn, err := proxyDial(pStr, targetAddr, timeoutMs)
				if err == nil {
					return conn, nil
				}
			}
			return nil, fmt.Errorf("all proxies in failover failed")
		},

		// UDPDial connects via UDP. Direct for now, but integrated into proxy interface.
		"UDPDial": func(targetAddr string, timeoutMs int64) (map[string]interface{}, error) {
			if timeoutMs <= 0 {
				timeoutMs = 5000
			}
			addr, err := net.ResolveUDPAddr("udp", targetAddr)
			if err != nil {
				return nil, err
			}
			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				return nil, err
			}
			return wrapPacketConn(conn), nil
		},

		// UDPAssociate requests a UDP relay from a SOCKS5 proxy.
		"UDPAssociate": func(proxyURLStr, clientAddr string) (string, error) {
			tc := &engine.TunnelConfig{Type: "proxy", URL: proxyURLStr}
			return proxy.HandleUDPAssociate(context.Background(), clientAddr, tc) // logic from socks5_udp.go
		},

		// UDPBind sets up a UDP listener for incoming data.
		"UDPBind": func(listenAddr string) (map[string]interface{}, error) {
			laddr, err := net.ResolveUDPAddr("udp", listenAddr)
			if err != nil {
				return nil, err
			}
			conn, err := net.ListenUDP("udp", laddr)
			if err != nil {
				return nil, err
			}
			return wrapPacketConn(conn), nil
		},

		// ClearPool removes all proxies from the pool.
		"ClearPool": func() {
			pool.mu.Lock()
			pool.proxies = nil
			pool.mu.Unlock()
		},

		// PoolSize returns the number of proxies in pool.
		"PoolSize": func() int {
			pool.mu.RLock()
			defer pool.mu.RUnlock()
			return len(pool.proxies)
		},
	}
}

func proxyDial(proxyURLStr, targetAddr string, timeoutMs int64) (map[string]interface{}, error) {
	pURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %v", err)
	}

	scheme := strings.ToLower(pURL.Scheme)
	timeout := time.Duration(timeoutMs) * time.Millisecond

	switch {
	case scheme == "socks5" || scheme == "socks5h":
		var auth *socks5proxy.Auth
		if pURL.User != nil {
			pass, _ := pURL.User.Password()
			auth = &socks5proxy.Auth{
				User:     pURL.User.Username(),
				Password: pass,
			}
		}
		dialer, err := socks5proxy.SOCKS5("tcp", pURL.Host, auth, &net.Dialer{Timeout: timeout})
		if err != nil {
			return nil, err
		}
		conn, err := dialer.Dial("tcp", targetAddr)
		if err != nil {
			return nil, err
		}
		return wrapNetConn(conn), nil

	case scheme == "http" || scheme == "https":
		// HTTP CONNECT proxy
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.Dial("tcp", pURL.Host)
		if err != nil {
			return nil, err
		}
		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
		if pURL.User != nil {
			// Basic auth
			pass, _ := pURL.User.Password()
			cred := pURL.User.Username() + ":" + pass
			encoded := base64Encode([]byte(cred))
			connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", encoded)
		}
		connectReq += "\r\n"
		_, err = conn.Write([]byte(connectReq))
		if err != nil {
			conn.Close()
			return nil, err
		}
		// Read response (simple)
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return nil, err
		}
		response := string(buf[:n])
		if !strings.Contains(response, "200") {
			conn.Close()
			return nil, fmt.Errorf("CONNECT failed: %s", response)
		}
		return wrapNetConn(conn), nil

	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", scheme)
	}
}

func wrapNetConn(conn net.Conn) map[string]interface{} {
	return map[string]interface{}{
		"Read": func(size int) ([]byte, error) {
			buf := make([]byte, size)
			n, err := conn.Read(buf)
			if err != nil {
				return nil, err
			}
			return buf[:n], nil
		},
		"Write": func(data interface{}) (int, error) {
			b := gojaToBytes(data)
			if b == nil {
				return 0, fmt.Errorf("invalid data type")
			}
			return conn.Write(b)
		},
		"Close": func() error {
			return conn.Close()
		},
		"LocalAddr": func() string {
			return conn.LocalAddr().String()
		},
		"RemoteAddr": func() string {
			return conn.RemoteAddr().String()
		},
	}
}

func wrapPacketConn(conn *net.UDPConn) map[string]interface{} {
	return map[string]interface{}{
		"ReadFrom": func(size int) (map[string]interface{}, error) {
			buf := make([]byte, size)
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"data": buf[:n],
				"addr": addr.String(),
			}, nil
		},
		"WriteTo": func(data interface{}, targetAddr string) (int, error) {
			b := gojaToBytes(data)
			if b == nil {
				return 0, fmt.Errorf("invalid data type")
			}
			addr, err := net.ResolveUDPAddr("udp", targetAddr)
			if err != nil {
				return 0, err
			}
			return conn.WriteToUDP(b, addr)
		},
		"Close": func() error {
			return conn.Close()
		},
		"LocalAddr": func() string {
			return conn.LocalAddr().String()
		},
	}
}

func testProxy(proxyURLStr, testURL string, timeoutMs int64) bool {
	pURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return false
	}

	transport := &http.Transport{
		TLSClientConfig: &ctls.Config{InsecureSkipVerify: true},
	}

	scheme := strings.ToLower(pURL.Scheme)
	switch {
	case scheme == "http" || scheme == "https":
		transport.Proxy = http.ProxyURL(pURL)
	case scheme == "socks5" || scheme == "socks5h":
		var auth *socks5proxy.Auth
		if pURL.User != nil {
			pass, _ := pURL.User.Password()
			auth = &socks5proxy.Auth{
				User:     pURL.User.Username(),
				Password: pass,
			}
		}
		dialer, err := socks5proxy.SOCKS5("tcp", pURL.Host, auth, socks5proxy.Direct)
		if err != nil {
			return false
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
	default:
		return false
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeoutMs) * time.Millisecond,
	}

	resp, err := client.Get(testURL)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func base64Encode(data []byte) string {
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0, (len(data)+2)/3*4)
	for i := 0; i < len(data); i += 3 {
		var b uint32
		n := 0
		for j := 0; j < 3 && i+j < len(data); j++ {
			b = (b << 8) | uint32(data[i+j])
			n++
		}
		b <<= uint(3-n) * 8
		result = append(result, b64[(b>>18)&0x3F])
		result = append(result, b64[(b>>12)&0x3F])
		if n >= 2 {
			result = append(result, b64[(b>>6)&0x3F])
		} else {
			result = append(result, '=')
		}
		if n >= 3 {
			result = append(result, b64[b&0x3F])
		} else {
			result = append(result, '=')
		}
	}
	return string(result)
}
