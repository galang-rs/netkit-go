package js

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"http-interperation/pkg/browser"
	"http-interperation/pkg/network"

	"golang.org/x/net/proxy"
)

// RegisterWebSocketModule extends the Net module with WebSocket client support.
// Uses the network.TLSDialer for TLS-fingerprinted connections.
//
// JS API:
//
//	var ws = Net.DialWS("wss://example.com/ws", {
//	    headers: { "Origin": "https://example.com" },
//	    profile: "chrome_120",
//	    agent: "socks5://proxy:1080",
//	    fingerprint: existingFP,
//	    subprotocols: ["binary"]
//	});
//	ws.SendBinary(data);
//	ws.SendText("hello");
//	var msg = ws.ReadMessage();  // { type: "binary"|"text", data: bytes|string }
//	ws.SetReadDeadline(5000);
//	ws.Ping();
//	ws.Close();
func RegisterWebSocketModule(r *Runtime, jsCtx map[string]interface{}) {
	netModule, ok := jsCtx["Net"].(map[string]interface{})
	if !ok {
		netModule = make(map[string]interface{})
		jsCtx["Net"] = netModule
	}

	netModule["DialWS"] = func(rawURL string, options ...map[string]interface{}) (map[string]interface{}, error) {
		// Parse URL
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("invalid URL: %v", err)
		}

		isSecure := u.Scheme == "wss"
		host := u.Host
		if !strings.Contains(host, ":") {
			if isSecure {
				host += ":443"
			} else {
				host += ":80"
			}
		}

		// Parse options
		customHeaders := http.Header{}
		profileName := ""
		proxyAddr := ""
		var subprotocols []string
		var profile *browser.Profile

		if len(options) > 0 {
			opts := options[0]
			if h, ok := opts["headers"].(map[string]interface{}); ok {
				for k, v := range h {
					customHeaders.Set(k, fmt.Sprintf("%v", v))
				}
			}
			if p, ok := opts["profile"].(string); ok {
				profileName = p
			}
			if a, ok := opts["agent"].(string); ok {
				proxyAddr = a
			}
			if sp, ok := opts["subprotocols"].([]interface{}); ok {
				for _, s := range sp {
					if str, ok := s.(string); ok {
						subprotocols = append(subprotocols, str)
					}
				}
			}
			if fp, ok := opts["fingerprint"]; ok {
				if p, ok := fp.(*browser.Profile); ok {
					profile = p
					profile.Repair()
				}
			}
		}

		// Generate browser profile for TLS fingerprinting
		if profile == nil {
			profile, err = browser.GenerateFromProfile(profileName)
			if err != nil {
				return nil, fmt.Errorf("failed to generate browser profile: %v", err)
			}
		}

		// Set default headers
		if customHeaders.Get("Origin") == "" {
			customHeaders.Set("Origin", fmt.Sprintf("https://%s", u.Hostname()))
		}
		if customHeaders.Get("User-Agent") == "" && profile != nil {
			customHeaders.Set("User-Agent", profile.UserAgent)
		}

		// Parse proxy
		var proxyHost string
		var proxyAuth *proxy.Auth
		if proxyAddr != "" {
			if pu, err := url.Parse(proxyAddr); err == nil && pu.Host != "" {
				proxyHost = pu.Host
				if pu.User != nil {
					proxyAuth = &proxy.Auth{User: pu.User.Username()}
					if p, ok := pu.User.Password(); ok {
						proxyAuth.Password = p
					}
				}
			}
		}

		// Connect using TLSDialer with fingerprint
		// IMPORTANT: Force HTTP/1.1 ALPN for WebSocket — h2 breaks WS upgrade handshake
		r.Unlock()
		var conn net.Conn
		if isSecure && profile != nil && profile.TLSProfile != nil {
			dialer, dialErr := network.NewTLSDialer(profile.TLSProfile, profile.TCPProfile, proxyHost, proxyAuth)
			if dialErr != nil {
				r.Lock()
				return nil, fmt.Errorf("failed to create TLS dialer: %v", dialErr)
			}
			// Extract hostname for SNI
			hostname := u.Hostname()
			// Force HTTP/1.1 only — WebSocket MUST NOT negotiate h2
			conn, err = dialer.DialTLSWithServerNameALPN("tcp", host, hostname, []string{"http/1.1"})
		} else {
			if proxyHost != "" {
				socksDialer, dialErr := proxy.SOCKS5("tcp", proxyHost, proxyAuth, proxy.Direct)
				if dialErr != nil {
					r.Lock()
					return nil, fmt.Errorf("proxy dial failed: %v", dialErr)
				}
				conn, err = socksDialer.Dial("tcp", host)
			} else {
				conn, err = net.DialTimeout("tcp", host, 30*time.Second)
			}
		}
		r.Lock()

		if err != nil {
			return nil, fmt.Errorf("WebSocket dial failed: %v", err)
		}

		// Perform WebSocket handshake
		wsKey := generateWSKey()
		path := u.RequestURI()
		if path == "" {
			path = "/"
		}

		// Build HTTP upgrade request
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("GET %s HTTP/1.1\r\n", path))
		sb.WriteString(fmt.Sprintf("Host: %s\r\n", u.Host))
		sb.WriteString("Upgrade: websocket\r\n")
		sb.WriteString("Connection: Upgrade\r\n")
		sb.WriteString(fmt.Sprintf("Sec-WebSocket-Key: %s\r\n", wsKey))
		sb.WriteString("Sec-WebSocket-Version: 13\r\n")
		if len(subprotocols) > 0 {
			sb.WriteString(fmt.Sprintf("Sec-WebSocket-Protocol: %s\r\n", strings.Join(subprotocols, ", ")))
		}
		for key, vals := range customHeaders {
			for _, val := range vals {
				sb.WriteString(fmt.Sprintf("%s: %s\r\n", key, val))
			}
		}
		sb.WriteString("\r\n")

		r.Unlock()
		_, err = conn.Write([]byte(sb.String()))
		if err != nil {
			conn.Close()
			r.Lock()
			return nil, fmt.Errorf("WebSocket handshake write failed: %v", err)
		}

		// Read handshake response
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		r.Lock()
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("WebSocket handshake response failed: %v", err)
		}
		if resp.StatusCode != 101 {
			conn.Close()
			return nil, fmt.Errorf("WebSocket handshake failed: HTTP %d", resp.StatusCode)
		}

		// Connection established, wrap it
		wsConn := &wsConnection{
			conn:   conn,
			reader: reader,
		}

		return wrapWSConn(r, wsConn, profile), nil
	}
}

// wsConnection wraps a net.Conn with WebSocket frame reading/writing.
type wsConnection struct {
	conn   net.Conn
	reader *bufio.Reader
}

// WebSocket opcodes
const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

// writeFrame writes a WebSocket frame (client-side, always masked).
func (ws *wsConnection) writeFrame(opcode byte, payload []byte) error {
	frame := buildWSFrame(opcode, payload)
	_, err := ws.conn.Write(frame)
	return err
}

// readFrame reads a single WebSocket frame.
func (ws *wsConnection) readFrame() (opcode byte, payload []byte, err error) {
	// Read first 2 bytes
	header := make([]byte, 2)
	if _, err = io.ReadFull(ws.reader, header); err != nil {
		return 0, nil, err
	}

	// fin := header[0] & 0x80
	opcode = header[0] & 0x0F
	masked := header[1] & 0x80
	payloadLen := uint64(header[1] & 0x7F)

	// Extended payload length
	if payloadLen == 126 {
		ext := make([]byte, 2)
		if _, err = io.ReadFull(ws.reader, ext); err != nil {
			return 0, nil, err
		}
		payloadLen = uint64(binary.BigEndian.Uint16(ext))
	} else if payloadLen == 127 {
		ext := make([]byte, 8)
		if _, err = io.ReadFull(ws.reader, ext); err != nil {
			return 0, nil, err
		}
		payloadLen = binary.BigEndian.Uint64(ext)
	}

	// Read masking key if present
	var maskKey []byte
	if masked != 0 {
		maskKey = make([]byte, 4)
		if _, err = io.ReadFull(ws.reader, maskKey); err != nil {
			return 0, nil, err
		}
	}

	// Read payload
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err = io.ReadFull(ws.reader, payload); err != nil {
			return 0, nil, err
		}
		// Unmask if needed (server frames usually aren't masked)
		if masked != 0 {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}
	}

	return opcode, payload, nil
}

// wrapWSConn creates a JS-accessible object for a WebSocket connection.
// Includes fingerprint.snapshoot() for TLS profile reuse (same pattern as fetch).
func wrapWSConn(r *Runtime, ws *wsConnection, profile *browser.Profile) map[string]interface{} {
	return map[string]interface{}{
		// fingerprint exposes the browser profile for reuse
		// across fetch/DialWS calls (TLS session continuity).
		"fingerprint": map[string]interface{}{
			"snapshoot": func() *browser.Profile {
				return profile
			},
		},
		// SendBinary sends a binary WebSocket frame.
		"SendBinary": func(data interface{}) error {
			b := gojaToBytes(data)
			if b == nil {
				return fmt.Errorf("invalid data type")
			}
			return ws.writeFrame(wsOpBinary, b)
		},
		// SendText sends a text WebSocket frame.
		"SendText": func(text string) error {
			return ws.writeFrame(wsOpText, []byte(text))
		},
		// ReadMessage reads the next WebSocket message.
		// Returns { type: "binary"|"text"|"close"|"ping"|"pong", data: bytes|string }
		"ReadMessage": func() (map[string]interface{}, error) {
			r.Unlock()
			opcode, payload, err := ws.readFrame()
			r.Lock()
			if err != nil {
				return nil, err
			}

			var typeStr string
			switch opcode {
			case wsOpText:
				typeStr = "text"
			case wsOpBinary:
				typeStr = "binary"
			case wsOpClose:
				typeStr = "close"
			case wsOpPing:
				typeStr = "ping"
				// Auto-reply with pong
				_ = ws.writeFrame(wsOpPong, payload)
			case wsOpPong:
				typeStr = "pong"
			default:
				typeStr = "unknown"
			}

			result := map[string]interface{}{
				"type": typeStr,
			}
			if opcode == wsOpText {
				result["data"] = string(payload)
			} else {
				result["data"] = payload
			}
			return result, nil
		},
		// SetReadDeadline sets timeout for read operations in milliseconds.
		"SetReadDeadline": func(ms int64) error {
			return ws.conn.SetReadDeadline(time.Now().Add(time.Duration(ms) * time.Millisecond))
		},
		// SetWriteDeadline sets timeout for write operations in milliseconds.
		"SetWriteDeadline": func(ms int64) error {
			return ws.conn.SetWriteDeadline(time.Now().Add(time.Duration(ms) * time.Millisecond))
		},
		// Ping sends a WebSocket ping frame.
		"Ping": func() error {
			return ws.writeFrame(wsOpPing, []byte{})
		},
		// Pong sends a WebSocket pong frame.
		"Pong": func(data []byte) error {
			return ws.writeFrame(wsOpPong, data)
		},
		// Close sends a close frame and closes the connection.
		"Close": func() error {
			closePayload := make([]byte, 2)
			binary.BigEndian.PutUint16(closePayload, 1000) // Normal closure
			_ = ws.writeFrame(wsOpClose, closePayload)
			return ws.conn.Close()
		},
		// CloseWithCode closes with a specific status code and reason.
		"CloseWithCode": func(code int, reason string) error {
			closePayload := make([]byte, 2+len(reason))
			binary.BigEndian.PutUint16(closePayload, uint16(code))
			copy(closePayload[2:], reason)
			_ = ws.writeFrame(wsOpClose, closePayload)
			return ws.conn.Close()
		},
		// LocalAddr returns the local network address.
		"LocalAddr": func() string {
			return ws.conn.LocalAddr().String()
		},
		// RemoteAddr returns the remote network address.
		"RemoteAddr": func() string {
			return ws.conn.RemoteAddr().String()
		},
		// SetReadLimit is not needed for raw implementation.
		"SetReadLimit": func(limit int64) {
			// No-op for raw implementation
		},
	}
}

// buildWSFrame builds a WebSocket frame (client-side, always masked per RFC 6455).
func buildWSFrame(opcode byte, payload []byte) []byte {
	payloadLen := len(payload)
	var frame []byte

	// First byte: FIN + opcode
	frame = append(frame, 0x80|opcode)

	// Second byte: MASK bit + payload length
	if payloadLen < 126 {
		frame = append(frame, 0x80|byte(payloadLen))
	} else if payloadLen < 65536 {
		frame = append(frame, 0x80|126)
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(payloadLen))
		frame = append(frame, lenBytes...)
	} else {
		frame = append(frame, 0x80|127)
		lenBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBytes, uint64(payloadLen))
		frame = append(frame, lenBytes...)
	}

	// Masking key (4 random bytes)
	maskKey := make([]byte, 4)
	rand.Read(maskKey)
	frame = append(frame, maskKey...)

	// Masked payload
	masked := make([]byte, payloadLen)
	for i := 0; i < payloadLen; i++ {
		masked[i] = payload[i] ^ maskKey[i%4]
	}
	frame = append(frame, masked...)

	return frame
}

// generateWSKey generates a random Sec-WebSocket-Key.
func generateWSKey() string {
	key := make([]byte, 16)
	rand.Read(key)
	return fmt.Sprintf("%x", key)[:24]
}
