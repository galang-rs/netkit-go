package js

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/bacot120211/netkit-go/pkg/adblock"
	"github.com/bacot120211/netkit-go/pkg/engine"
)

// RegisterFlowModule injects ctx.Flow into the JS context.
// Provides protocol detection, direction awareness, and flow intelligence.
func RegisterFlowModule(jsCtx map[string]interface{}, ctx *engine.PacketContext) {
	if ctx == nil || ctx.Packet == nil {
		return
	}

	pkt := ctx.Packet
	payload := pkt.Payload

	var host, path, scheme string

	// HTTP Correlation logic
	var refID interface{}
	var fullURL string
	if ctx.Session != nil {
		if IsHTTPRequest(payload) {
			refID = pkt.ID
			ctx.Session.Data.Store("last_http_req_id", pkt.ID)

			// Track path and host for FullURL & responses
			host = pkt.Dest
			if h, ok := pkt.Metadata["Hostname"].(string); ok && h != "" {
				host = h
			} else if h, ok := pkt.Metadata["hostname"].(string); ok && h != "" {
				host = h
			}

			path = "/"
			if req := ParseHTTPRequest(payload); req != nil {
				if p, ok := req["path"].(string); ok {
					path = p
				}
				// Use Host header if available (case-insensitive)
				if headers, ok := req["headers"].(map[string]interface{}); ok {
					for k, v := range headers {
						if strings.ToLower(k) == "host" {
							host = fmt.Sprintf("%v", v)
							break
						}
					}
				}
			}
			ctx.Session.Data.Store("last_http_path", path)
			ctx.Session.Data.Store("Hostname", host)
			// Store request status and headers
			if h := ParseHTTPRequest(payload); h != nil {
				ctx.Session.Data.Store("last_http_req_headers", h["headers"])
				ctx.Session.Data.Store("is_http_req", true)
				ctx.Session.Data.Store("is_http_resp", false)
			}

			scheme := "http"
			if pkt.DestPort == 443 || pkt.DestPort == 8443 {
				scheme = "https"
			}
			fullURL = fmt.Sprintf("%s://%s%s", scheme, host, path)
			ctx.Session.Data.Store("last_http_full_url", fullURL)
		} else if IsHTTPResponse(payload) {
			if val, ok := ctx.Session.Data.Load("last_http_req_id"); ok {
				refID = val
			}
			ctx.Session.Data.Store("is_http_resp", true)
			ctx.Session.Data.Store("is_http_req", false)

			// Reconstruct URL from session or Metadata
			host = pkt.Source // IP Fallback
			if h, ok := pkt.Metadata["Hostname"].(string); ok && h != "" {
				host = h
			} else if h, ok := pkt.Metadata["hostname"].(string); ok && h != "" {
				host = h
			} else if hostRaw, ok := ctx.Session.Data.Load("Hostname"); ok {
				if h, ok := hostRaw.(string); ok && h != "" {
					host = h
				}
			}

			path = "/"
			if pathRaw, ok := ctx.Session.Data.Load("last_http_path"); ok {
				if p, ok := pathRaw.(string); ok && p != "" {
					path = p
				}
			}

			scheme = "http"
			if pkt.SourcePort == 443 || pkt.SourcePort == 8443 {
				scheme = "https"
			}
			fullURL = fmt.Sprintf("%s://%s%s", scheme, host, path)
		} else {
			// Continuation packet check
			if val, ok := ctx.Session.Data.Load("is_http_req"); ok && val.(bool) {
				if reqVal, ok := ctx.Session.Data.Load("last_http_req_id"); ok {
					refID = reqVal
				}

				// Reconstruct URL from session only if it's decrypted traffic
				if dec, ok := pkt.Metadata["Decrypted"].(bool); ok && dec {
					if urlVal, ok := ctx.Session.Data.Load("last_http_full_url"); ok {
						fullURL = urlVal.(string)
					} else {
						host := pkt.Dest
						if hostRaw, ok := ctx.Session.Data.Load("Hostname"); ok {
							host = hostRaw.(string)
						}
						path := "/"
						if pathRaw, ok := ctx.Session.Data.Load("last_http_path"); ok {
							path = pathRaw.(string)
						}
						scheme := "http"
						if pkt.DestPort == 443 || pkt.DestPort == 8443 {
							scheme = "https"
						}
						fullURL = fmt.Sprintf("%s://%s%s", scheme, host, path)
					}
				}
			}
			if val, ok := ctx.Session.Data.Load("is_http_resp"); ok && val.(bool) {
				if reqVal, ok := ctx.Session.Data.Load("last_http_req_id"); ok {
					refID = reqVal
				}

				// Reconstruct URL from session only if it's decrypted traffic
				if dec, ok := pkt.Metadata["Decrypted"].(bool); ok && dec {
					if urlVal, ok := ctx.Session.Data.Load("last_http_full_url"); ok {
						fullURL = urlVal.(string)
					} else {
						// Reconstruct URL from session
						host := pkt.Source
						if hostRaw, ok := ctx.Session.Data.Load("Hostname"); ok {
							host = hostRaw.(string)
						}
						path := "/"
						if pathRaw, ok := ctx.Session.Data.Load("last_http_path"); ok {
							path = pathRaw.(string)
						}
						scheme := "http"
						if pkt.SourcePort == 443 || pkt.SourcePort == 8443 {
							scheme = "https"
						}
						fullURL = fmt.Sprintf("%s://%s%s", scheme, host, path)
					}
				}
			}
		}
	}

	jsCtx["Flow"] = map[string]interface{}{
		// ID returns a unique flow identifier based on src:port <-> dst:port.
		"ID": func() string {
			return flowID(pkt)
		},

		// Direction returns "inbound" or "outbound" based on port heuristic.
		// Ports < 1024 on dest are considered outbound (client -> server).
		"Direction": func() string {
			if pkt.DestPort < 1024 {
				return "outbound"
			}
			if pkt.SourcePort < 1024 {
				return "inbound"
			}
			return "unknown"
		},

		// IsFirstPacket checks if payload looks like a connection initiation.
		"IsFirstPacket": func() bool {
			if len(payload) == 0 {
				return false
			}
			// SYN-like heuristic: TLS ClientHello or HTTP request start
			if IsTLSClientHello(payload) {
				return true
			}
			if IsHTTPRequest(payload) {
				return true
			}
			return false
		},

		// IsTLSHandshake checks if payload starts with TLS handshake byte.
		"IsTLSHandshake": func() bool {
			return IsTLSHandshake(payload)
		},

		// IsTLSClientHello checks specifically for ClientHello.
		"IsTLSClientHello": func() bool {
			return IsTLSClientHello(payload)
		},

		// IsTLSServerHello checks specifically for ServerHello.
		"IsTLSServerHello": func() bool {
			if len(payload) < 6 {
				return false
			}
			return payload[0] == 0x16 && payload[5] == 0x02
		},

		// IsHTTP checks if payload looks like an HTTP request or response.
		"IsHTTP": func() bool {
			if IsHTTPRequest(payload) || IsHTTPResponse(payload) {
				return true
			}
			if ctx.Session != nil {
				if v, ok := ctx.Session.Data.Load("is_http_req"); ok && v.(bool) {
					return true
				}
				if v, ok := ctx.Session.Data.Load("is_http_resp"); ok && v.(bool) {
					return true
				}
			}
			return false
		},

		// IsHTTPRequest checks for HTTP request specifically.
		"IsHTTPRequest": func() bool {
			if IsHTTPRequest(payload) {
				return true
			}
			// Continuation check: only if session is marked as HTTP AND it's decrypted traffic
			if ctx.Session != nil {
				if v, ok := ctx.Session.Data.Load("is_http_req"); ok && v.(bool) {
					if dec, ok := pkt.Metadata["Decrypted"].(bool); ok && dec {
						return true
					}
				}
			}
			return false
		},

		// IsHTTPResponse checks for HTTP response specifically.
		"IsHTTPResponse": func() bool {
			if IsHTTPResponse(payload) {
				return true
			}
			// Continuation check: only if session is marked as HTTP AND it's decrypted traffic
			if ctx.Session != nil {
				if v, ok := ctx.Session.Data.Load("is_http_resp"); ok && v.(bool) {
					if dec, ok := pkt.Metadata["Decrypted"].(bool); ok && dec {
						return true
					}
				}
			}
			return false
		},

		// IsWebSocket checks for WebSocket upgrade or frame.
		"IsWebSocket": func() bool {
			s := string(payload)
			ls := strings.ToLower(s)
			if strings.Contains(ls, "upgrade: websocket") {
				return true
			}
			// Check for WS frame: first byte has FIN + opcode
			if len(payload) >= 2 {
				fin := payload[0] & 0x80
				opcode := payload[0] & 0x0F
				if fin != 0 && opcode >= 0x01 && opcode <= 0x0A {
					return true
				}
			}
			return false
		},

		// IsDNS heuristic: UDP port 53 or payload starts with DNS-like structure.
		"IsDNS": func() bool {
			if pkt.DestPort == 53 || pkt.SourcePort == 53 {
				return true
			}
			if strings.ToLower(pkt.Protocol) == "udp" && len(payload) > 12 {
				return true
			}
			return false
		},

		// IsQUIC checks for QUIC initial packets.
		"IsQUIC": func() bool {
			if len(payload) < 5 {
				return false
			}
			// QUIC long header form bit
			if payload[0]&0x80 != 0 {
				// Check for QUIC version
				if len(payload) >= 5 {
					ver := binary.BigEndian.Uint32(payload[1:5])
					// Known QUIC versions
					if ver == 0x00000001 || ver == 0xff00001d || ver == 0xff00001e || ver == 0x51303530 {
						return true
					}
				}
			}
			// UDP on port 443 is often QUIC
			if pkt.DestPort == 443 && strings.ToLower(pkt.Protocol) == "udp" {
				return true
			}
			return false
		},

		// ProtocolGuess returns best guess of the application protocol.
		"ProtocolGuess": func() string {
			if IsTLSHandshake(payload) {
				return "TLS"
			}
			if IsHTTPRequest(payload) || IsHTTPResponse(payload) {
				return "HTTP"
			}
			if pkt.DestPort == 53 || pkt.SourcePort == 53 {
				return "DNS"
			}
			if pkt.DestPort == 443 && strings.ToLower(pkt.Protocol) == "udp" {
				return "QUIC"
			}
			s := strings.ToLower(string(payload))
			if strings.Contains(s, "upgrade: websocket") {
				return "WebSocket"
			}
			if pkt.DestPort == 22 || pkt.SourcePort == 22 {
				return "SSH"
			}
			if pkt.DestPort == 21 || pkt.SourcePort == 21 {
				return "FTP"
			}
			if pkt.DestPort == 25 || pkt.SourcePort == 25 {
				return "SMTP"
			}
			if pkt.DestPort == 3306 || pkt.SourcePort == 3306 {
				return "MySQL"
			}
			if pkt.DestPort == 5432 || pkt.SourcePort == 5432 {
				return "PostgreSQL"
			}
			if pkt.DestPort == 6379 || pkt.SourcePort == 6379 {
				return "Redis"
			}
			return "UNKNOWN"
		},

		// PayloadSize returns the payload length.
		"PayloadSize": func() int {
			return len(payload)
		},

		// Protocol returns the transport protocol (TCP/UDP).
		"Protocol": pkt.Protocol,
		"Src":      pkt.Source,
		"Dst":      pkt.Dest,
		"SrcPort":  pkt.SourcePort,
		"DstPort":  pkt.DestPort,

		// Headers() returns HTTP headers as a map if the payload is an HTTP request or response.
		// Returns nil if no HTTP headers are detected.
		// Resulting object includes .Json() and .Raw() methods.
		"Headers": func() interface{} {
			var h map[string]interface{}
			if IsHTTPRequest(payload) {
				req := ParseHTTPRequest(payload)
				if req != nil {
					h = req["headers"].(map[string]interface{})
				}
			} else if IsHTTPResponse(payload) {
				resp := ParseHTTPResponse(payload)
				if resp != nil {
					h = resp["headers"].(map[string]interface{})
					// Store headers in session for continuation packets
					if ctx.Session != nil {
						ctx.Session.Data.Store("last_http_resp_headers", h)
						ctx.Session.Data.Store("is_http_resp", true)
					}
				}
			} else if ctx.Session != nil {
				// Continuation packet: retrieve cached headers
				if v, ok := ctx.Session.Data.Load("is_http_req"); ok && v.(bool) {
					if hVal, ok := ctx.Session.Data.Load("last_http_req_headers"); ok {
						h = hVal.(map[string]interface{})
					}
				} else if v, ok := ctx.Session.Data.Load("is_http_resp"); ok && v.(bool) {
					if hVal, ok := ctx.Session.Data.Load("last_http_resp_headers"); ok {
						h = hVal.(map[string]interface{})
					}
				}
			}

			if h == nil {
				return nil
			}

			// Capture raw header block
			headerEnd := bytes.Index(payload, []byte("\r\n\r\n"))
			if headerEnd == -1 {
				headerEnd = bytes.Index(payload, []byte("\n\n"))
			}
			rawHeaders := ""
			if headerEnd != -1 {
				rawHeaders = string(payload[:headerEnd])
			}

			res := make(map[string]interface{})
			for k, v := range h {
				res[k] = v
			}
			// Add .Json() method
			res["Json"] = func() string {
				b, _ := json.Marshal(h)
				return string(b)
			}
			// Add .Raw() method (pure original)
			res["Raw"] = func() string {
				return rawHeaders
			}
			return res
		},

		// Body() returns a smart object containing the HTTP body.
		// It automatically filters out GET/HEAD requests to avoid redundant logging of empty bodies.
		// The returned object includes .Raw() and .Json() methods.
		"Body": func() interface{} {
			var body []byte
			var contentType string
			var contentEncoding string
			var transferEncoding string

			if IsHTTPRequest(payload) {
				req := ParseHTTPRequest(payload)
				if req != nil {
					method, _ := req["method"].(string)
					method = strings.ToUpper(method)
					body = req["body"].([]byte)
					if headers, ok := req["headers"].(map[string]interface{}); ok {
						for k, v := range headers {
							lk := strings.ToLower(k)
							if lk == "content-type" {
								contentType = v.(string)
							} else if lk == "content-encoding" {
								contentEncoding = v.(string)
							} else if lk == "transfer-encoding" {
								transferEncoding = v.(string)
							}
						}
					}
				}
			} else if IsHTTPResponse(payload) {
				resp := ParseHTTPResponse(payload)
				if resp != nil {
					body = resp["body"].([]byte)
					if headers, ok := resp["headers"].(map[string]interface{}); ok {
						for k, v := range headers {
							lk := strings.ToLower(k)
							if lk == "content-type" {
								contentType = v.(string)
							} else if lk == "content-encoding" {
								contentEncoding = v.(string)
							} else if lk == "transfer-encoding" {
								transferEncoding = v.(string)
							}
						}
					}
				}
			} else if ctx.Session != nil {
				// Continuation packet: body is the whole payload
				body = payload
				// Try to retrieve content-type from session if available
				if v, ok := ctx.Session.Data.Load("last_http_resp_headers"); ok {
					if h, ok := v.(map[string]interface{}); ok {
						for k, val := range h {
							lk := strings.ToLower(k)
							if lk == "content-type" {
								contentType, _ = val.(string)
							} else if lk == "content-encoding" {
								contentEncoding, _ = val.(string)
							} else if lk == "transfer-encoding" {
								transferEncoding, _ = val.(string)
							}
						}
					}
				}
			}

			if body == nil {
				return nil
			}

			// De-chunk if needed
			if strings.Contains(strings.ToLower(transferEncoding), "chunked") {
				body = Dechunk(body)
			}

			// Decompress if needed
			if contentEncoding != "" {
				if decoded, err := decompressBody(body, contentEncoding); err == nil {
					body = decoded
				}
			}

			// Build smart body object
			res := make(map[string]interface{})

			// Detect stream properties
			isStream := strings.Contains(contentType, "text/event-stream") ||
				strings.Contains(strings.ToLower(transferEncoding), "chunked") ||
				bytes.Contains(body, []byte("data:"))

			res["IsStream"] = func() bool {
				return isStream
			}

			// WaitFullContent buffers the flow in session and returns the full body when complete.
			res["WaitFullContent"] = func() interface{} {
				if ctx.Session == nil {
					return nil
				}

				// Generate a unique transaction key for buffering
				direction := "req"
				if IsHTTPResponse(payload) || (ctx.Session != nil && !IsHTTPRequest(payload)) {
					// Check session for response state if not explicit
					if v, ok := ctx.Session.Data.Load("is_http_resp"); ok && v.(bool) {
						direction = "resp"
					}
				}
				if IsHTTPResponse(payload) {
					direction = "resp"
				}

				txKey := fmt.Sprintf("body_buf_%s_%v", direction, refID)
				if refID == nil {
					txKey = fmt.Sprintf("body_buf_%s_%s_%d", direction, flowID(pkt), pkt.DestPort)
				}

				type bodyBuffer struct {
					Data          []byte
					LastPktID     uint64
					ContentLength int64
					IsChunked     bool
					Encoding      string
					IsComplete    bool
				}

				var buf *bodyBuffer
				if val, ok := ctx.Session.Data.Load(txKey); ok {
					buf = val.(*bodyBuffer)
				} else {
					// Initialize new buffer from headers
					cl := int64(-1)
					if IsHTTPRequest(payload) {
						if r := ParseHTTPRequest(payload); r != nil {
							if headers, ok := r["headers"].(map[string]interface{}); ok {
								for k, v := range headers {
									if strings.ToLower(k) == "content-length" {
										fmt.Sscanf(v.(string), "%d", &cl)
									}
								}
							}
						}
					} else if IsHTTPResponse(payload) {
						if r := ParseHTTPResponse(payload); r != nil {
							if headers, ok := r["headers"].(map[string]interface{}); ok {
								for k, v := range headers {
									if strings.ToLower(k) == "content-length" {
										fmt.Sscanf(v.(string), "%d", &cl)
									}
								}
							}
						}
					}

					buf = &bodyBuffer{
						Data:          []byte{},
						ContentLength: cl,
						IsChunked:     strings.Contains(strings.ToLower(transferEncoding), "chunked"),
						Encoding:      contentEncoding,
					}
				}

				// Avoid double-appending if called multiple times for same packet
				if buf.LastPktID != pkt.ID {
					// IMPORTANT: Append original unprocessed payload if it's a continuation,
					// or the parsed body if it's the first packet.
					var rawPiece []byte
					if IsHTTPRequest(payload) || IsHTTPResponse(payload) {
						if IsHTTPRequest(payload) {
							if r := ParseHTTPRequest(payload); r != nil {
								rawPiece = r["body"].([]byte)
							}
						} else {
							if r := ParseHTTPResponse(payload); r != nil {
								rawPiece = r["body"].([]byte)
							}
						}
					} else {
						rawPiece = payload
					}

					buf.Data = append(buf.Data, rawPiece...)
					buf.LastPktID = pkt.ID

					// Check for completion
					if buf.ContentLength >= 0 && int64(len(buf.Data)) >= buf.ContentLength {
						buf.IsComplete = true
					} else if buf.IsChunked && bytes.HasSuffix(payload, []byte("0\r\n\r\n")) {
						buf.IsComplete = true
					} else if !buf.IsChunked && buf.ContentLength == -1 && !isStream {
						buf.IsComplete = true
					}
					ctx.Session.Data.Store(txKey, buf)
				}

				if buf.IsComplete {
					finalBody := buf.Data
					if buf.IsChunked {
						finalBody = Dechunk(finalBody)
					}
					if buf.Encoding != "" {
						if decoded, err := decompressBody(finalBody, buf.Encoding); err == nil {
							finalBody = decoded
						}
					}
					return string(finalBody)
				}

				return nil
			}

			// Detect and parse body content
			contentType = strings.ToLower(contentType)
			isParsed := false

			// Helper to try parsing JSON from a byte slice
			tryParseJSON := func(b []byte) bool {
				// Clean up common SSE prefixes
				s := strings.TrimSpace(string(b))
				if strings.HasPrefix(s, "data:") {
					s = strings.TrimSpace(strings.TrimPrefix(s, "data:"))
				}

				var jsonData interface{}
				if err := json.Unmarshal([]byte(s), &jsonData); err == nil {
					if m, ok := jsonData.(map[string]interface{}); ok {
						for k, v := range m {
							res[k] = v
						}
						return true
					}
					// If it's an array, we can't merge it into res easily but we can store it
					res["_data"] = jsonData
					return true
				}
				return false
			}

			if strings.Contains(contentType, "application/json") || strings.Contains(contentType, "text/event-stream") || bytes.Contains(body, []byte("data:")) {
				isParsed = tryParseJSON(body)
				// If parsing failed or we suspect it's a stream, try parsing multiple data: lines
				if !isParsed || bytes.Contains(body, []byte("\ndata:")) || bytes.Contains(body, []byte("\rdata:")) {
					lines := strings.Split(string(body), "\n")
					var results []interface{}
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if strings.HasPrefix(line, "data:") {
							line = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
							// Filter out common markers like [DONE]
							if line == "[DONE]" {
								continue
							}
							var lineData interface{}
							if err := json.Unmarshal([]byte(line), &lineData); err == nil {
								results = append(results, lineData)
							}
						}
					}
					if len(results) > 0 {
						// Merge first result into root for convenience if only one
						if !isParsed && len(results) == 1 {
							if m, ok := results[0].(map[string]interface{}); ok {
								for k, v := range m {
									res[k] = v
								}
								isParsed = true
							}
						}
						res["events"] = results
						isParsed = true
					}
				}
			} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
				if vals, err := url.ParseQuery(string(body)); err == nil {
					for k, v := range vals {
						if len(v) == 1 {
							res[k] = v[0]
						} else {
							res[k] = v
						}
					}
					isParsed = true
				}
			}

			// Fallback: try parsing as JSON anyway if it looks like it
			if !isParsed {
				isParsed = tryParseJSON(body)
			}

			// Helper to check if string is printable text
			isText := func(b []byte) bool {
				if len(b) == 0 {
					return true
				}
				for _, x := range b {
					if x < 32 && x != 9 && x != 10 && x != 13 {
						return false
					}
				}
				return true
			}

			// Add .Raw() method
			res["Raw"] = func() string {
				if isText(body) {
					return string(body)
				}
				// Return hex for binary data to avoid junk
				return fmt.Sprintf("[Binary Data: %d bytes]", len(body))
			}
			// Add .Json() method
			res["Json"] = func() string {
				if isParsed {
					// Marshal only the parsed fields (Goja skips functions)
					b, _ := json.Marshal(res)
					return string(b)
				}
				if isText(body) {
					// Wrap raw string in JSON if not parsed but is text
					b, _ := json.Marshal(string(body))
					return string(b)
				}
				return `{"error": "binary data"}`
			}

			return res
		},

		// Snapshot() provides a unified view of the current flow state, including:
		// - Connection details (id, src, dst, ports, protocol)
		// - Reference/Lineage ID for HTTP correlation
		// - Metadata-based fingerprints (JA3, JA4, Akamai, Cloudflare)
		// - HTTP request/response details (method, path, headers, body, body_raw)
		// - Current global FS cache values
		"Snapshot": func() map[string]interface{} {
			snap := map[string]interface{}{
				"id":        flowID(pkt),
				"src":       pkt.Source,
				"dst":       pkt.Dest,
				"srcPort":   pkt.SourcePort,
				"dstPort":   pkt.DestPort,
				"protocol":  pkt.Protocol,
				"payload":   string(payload),
				"timestamp": pkt.Timestamp,
				"reference": refID,
			}

			// Add fingerprint info if present in metadata
			if pkt.Metadata != nil {
				for k, v := range pkt.Metadata {
					if strings.Contains(strings.ToLower(k), "fingerprint") ||
						strings.Contains(strings.ToLower(k), "ja3") ||
						strings.Contains(strings.ToLower(k), "ja4") ||
						strings.Contains(strings.ToLower(k), "akamai") ||
						strings.Contains(strings.ToLower(k), "cloudflare") {
						snap[k] = v
					}
				}
			}

			// Add HTTP info if detected
			if IsHTTPRequest(payload) {
				snap["http_type"] = "request"
				req := ParseHTTPRequest(payload)
				if req != nil {
					snap["headers"] = req["headers"]
					snap["method"] = req["method"]
					snap["path"] = req["path"]
					if b := req["body"]; b != nil && len(b.([]byte)) > 0 {
						body := b.([]byte)
						encoding := GetHTTPHeaderEx(payload, "Content-Encoding")
						transferEnc := GetHTTPHeaderEx(payload, "Transfer-Encoding")
						if strings.Contains(strings.ToLower(transferEnc), "chunked") {
							body = Dechunk(body)
						}
						snap["body_raw"] = string(body)
						if decoded, err := decompressBody(body, encoding); err == nil {
							snap["body"] = string(decoded)
						} else {
							snap["body"] = string(body)
						}
					}
				}
			} else if IsHTTPResponse(payload) {
				snap["http_type"] = "response"
				resp := ParseHTTPResponse(payload)
				if resp != nil {
					snap["headers"] = resp["headers"]
					snap["statusCode"] = resp["statusCode"]
					if b := resp["body"]; b != nil && len(b.([]byte)) > 0 {
						body := b.([]byte)
						encoding := GetHTTPHeaderEx(payload, "Content-Encoding")
						transferEnc := GetHTTPHeaderEx(payload, "Transfer-Encoding")
						if strings.Contains(strings.ToLower(transferEnc), "chunked") {
							body = Dechunk(body)
						}
						snap["body_raw"] = string(body)
						if decoded, err := decompressBody(body, encoding); err == nil {
							snap["body"] = string(decoded)
						} else {
							snap["body"] = string(body)
						}
					}
				}
			}

			// Add cache values (non-nil)
			cache := make(map[string]interface{})
			globalCache.Range(func(key, value interface{}) bool {
				if value != nil {
					cache[fmt.Sprintf("%v", key)] = value
				}
				return true
			})
			if len(cache) > 0 {
				snap["cache"] = cache
			}

			return snap
		},

		// Reference returns a correlation ID. For HTTP responses, it returns the ID
		// of the corresponding request within the same session.
		"Reference": func() interface{} {
			return refID
		},

		// FullURL returns the complete URL string (reconstructed for responses).
		"FullURL": fullURL,

		// UpdateBody replaces the current packet body and automatically updates Content-Length.
		// It also removes Content-Encoding if present to ensure the new body is readable.
		"UpdateBody": func(newBody interface{}) {
			data := gojaToBytes(newBody)
			if data == nil {
				return
			}

			// Update payload
			headerEnd := bytes.Index(pkt.Payload, []byte("\r\n\r\n"))
			if headerEnd == -1 {
				headerEnd = bytes.Index(pkt.Payload, []byte("\n\n"))
			}

			if headerEnd != -1 {
				sep := []byte("\r\n\r\n")
				if pkt.Payload[headerEnd] == '\n' && pkt.Payload[headerEnd+1] == '\n' {
					sep = []byte("\n\n")
				}

				headers := pkt.Payload[:headerEnd+len(sep)]
				// Update Content-Length and remove Content-Encoding
				headers = modifyHTTPHeader(headers, "Content-Length", itoa(len(data)))
				headers = removeHTTPHeader(headers, "Content-Encoding")

				// Check if headers end with separator, if not add it
				if !bytes.HasSuffix(headers, sep) {
					headers = append(bytes.TrimRight(headers, "\r\n"), sep...)
				}

				pkt.Payload = append(headers, data...)
			} else {
				// Not a standard HTTP packet with headers, just replace payload?
				pkt.Payload = data
			}

			ctx.Action = engine.ActionModified
		},
		// InjectJS(code) prepends a <script> block to the HTML body.
		"InjectJS": func(code string) {
			if code == "" {
				return
			}
			script := fmt.Sprintf("<script>%s</script>", code)

			var body []byte
			var encoding string
			if IsHTTPResponse(pkt.Payload) {
				resp := ParseHTTPResponse(pkt.Payload)
				if resp != nil {
					body = resp["body"].([]byte)
					if h, ok := resp["headers"].(map[string]interface{}); ok {
						for k, v := range h {
							if strings.ToLower(k) == "content-encoding" {
								encoding, _ = v.(string)
								break
							}
						}
					}
				}
			} else {
				body = pkt.Payload
			}

			if len(body) == 0 {
				return
			}

			// Decompress to inject safely
			data := body
			if encoding != "" {
				if decoded, err := decompressBody(body, encoding); err == nil {
					data = decoded
				}
			}

			// Prepend script
			data = append([]byte(script), data...)

			// Update using internal logic
			headerEnd := bytes.Index(pkt.Payload, []byte("\r\n\r\n"))
			if headerEnd == -1 {
				headerEnd = bytes.Index(pkt.Payload, []byte("\n\n"))
			}

			if headerEnd != -1 {
				sep := []byte("\r\n\r\n")
				if pkt.Payload[headerEnd] == '\n' && pkt.Payload[headerEnd+1] == '\n' {
					sep = []byte("\n\n")
				}
				headers := pkt.Payload[:headerEnd+len(sep)]
				headers = modifyHTTPHeader(headers, "Content-Length", itoa(len(data)))
				headers = removeHTTPHeader(headers, "Content-Encoding")
				pkt.Payload = append(headers, data...)
				ctx.Action = engine.ActionModified
			}
		},
		// Sanitize() automatically cleans the HTML body of ads using the built-in engine.
		"Sanitize": func() {
			var body []byte
			var encoding string

			// Extract body and encoding from headers
			if IsHTTPResponse(pkt.Payload) {
				resp := ParseHTTPResponse(pkt.Payload)
				if resp != nil {
					body = resp["body"].([]byte)
					if h, ok := resp["headers"].(map[string]interface{}); ok {
						for k, v := range h {
							if strings.ToLower(k) == "content-encoding" {
								encoding, _ = v.(string)
								break
							}
						}
					}
				}
			} else {
				// For continuation packets, try to find encoding in session
				body = pkt.Payload
				if ctx.Session != nil {
					if v, ok := ctx.Session.Data.Load("last_http_resp_headers"); ok {
						if h, ok := v.(map[string]interface{}); ok {
							for k, val := range h {
								if strings.ToLower(k) == "content-encoding" {
									encoding, _ = val.(string)
									break
								}
							}
						}
					}
				}
			}

			if len(body) == 0 {
				return
			}

			// Decompress if needed
			var sanitized string
			if encoding != "" {
				if decoded, err := decompressBody(body, encoding); err == nil {
					sanitized = adblock.SanitizeHTML(string(decoded))
				}
			} else {
				sanitized = adblock.SanitizeHTML(string(body))
			}

			// Only update if changed
			if sanitized != "" && (encoding != "" || sanitized != string(body)) {
				// Re-use UpdateBody logic within Sanitize
				// (Since UpdateBody is already in the map, we can't call it directly easily,
				// so we replicate the header modification logic or just call it if we restructure).
				// For now, let's just make sure UpdateBody is available or use its internal logic.

				// Re-applying UpdateBody logic here for simplicity in one tool call
				data := []byte(sanitized)
				headerEnd := bytes.Index(pkt.Payload, []byte("\r\n\r\n"))
				if headerEnd == -1 {
					headerEnd = bytes.Index(pkt.Payload, []byte("\n\n"))
				}

				if headerEnd != -1 {
					sep := []byte("\r\n\r\n")
					if pkt.Payload[headerEnd] == '\n' && pkt.Payload[headerEnd+1] == '\n' {
						sep = []byte("\n\n")
					}
					headers := pkt.Payload[:headerEnd+len(sep)]
					headers = modifyHTTPHeader(headers, "Content-Length", itoa(len(data)))
					headers = removeHTTPHeader(headers, "Content-Encoding")
					pkt.Payload = append(headers, data...)
					ctx.Action = engine.ActionModified
				}
			}
		},
	}
}

func flowID(pkt *engine.Packet) string {
	return pkt.Source + ":" + itoa(int(pkt.SourcePort)) + "->" + pkt.Dest + ":" + itoa(int(pkt.DestPort))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func IsTLSHandshake(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	return data[0] == 0x16 && data[1] == 0x03
}

func IsTLSClientHello(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	return data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01
}

func decompressBody(data []byte, encoding string) ([]byte, error) {
	encoding = strings.ToLower(encoding)
	switch encoding {
	case "gzip":
		return decompressGzip(data)
	case "deflate":
		return decompressDeflate(data)
	case "br":
		return decompressBrotli(data)
	default:
		return data, nil
	}
}
