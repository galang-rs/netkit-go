package js

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/ipv4"
)

// RegisterNetModule injects ctx.Net into the JS context.
// Provides TCP/UDP dial, connection Read/Write/Close, deadlines, keepalive.
func RegisterNetModule(r *Runtime, jsCtx map[string]interface{}) {
	// r.vm is used implicitly if needed, or we can just not declare it if unused.
	// Actually wrapConn uses it in a closure usually.
	vm := r.vm
	_ = vm // Avoid unused error if not used in this scope but maybe in closures

	// wrapConn creates a JS object representing a net.Conn
	wrapConn := func(conn net.Conn) map[string]interface{} {
		return map[string]interface{}{
			"Read": func(size int) ([]byte, error) {
				buf := make([]byte, size)
				n, err := conn.Read(buf)
				if err != nil {
					return nil, err
				}
				return buf[:n], nil
			},
			"ReadAll": func() ([]byte, error) {
				var result []byte
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						result = append(result, buf[:n]...)
					}
					if err != nil {
						break
					}
				}
				return result, nil
			},
			"Write": func(data interface{}) (int, error) {
				b := gojaToBytes(data)
				if b == nil {
					return 0, fmt.Errorf("invalid data type")
				}
				return conn.Write(b)
			},
			"WriteString": func(s string) (int, error) {
				return conn.Write([]byte(s))
			},
			"Close": func() error {
				return conn.Close()
			},
			"CloseWrite": func() error {
				if tc, ok := conn.(*net.TCPConn); ok {
					return tc.CloseWrite()
				}
				return fmt.Errorf("not a TCP connection")
			},
			"CloseRead": func() error {
				if tc, ok := conn.(*net.TCPConn); ok {
					return tc.CloseRead()
				}
				return fmt.Errorf("not a TCP connection")
			},
			"SetDeadline": func(ms int64) error {
				return conn.SetDeadline(time.Now().Add(time.Duration(ms) * time.Millisecond))
			},
			"SetReadDeadline": func(ms int64) error {
				return conn.SetReadDeadline(time.Now().Add(time.Duration(ms) * time.Millisecond))
			},
			"SetWriteDeadline": func(ms int64) error {
				return conn.SetWriteDeadline(time.Now().Add(time.Duration(ms) * time.Millisecond))
			},
			"SetKeepAlive": func(enable bool) error {
				if tc, ok := conn.(*net.TCPConn); ok {
					return tc.SetKeepAlive(enable)
				}
				return fmt.Errorf("not a TCP connection")
			},
			"SetKeepAlivePeriod": func(seconds int) error {
				if tc, ok := conn.(*net.TCPConn); ok {
					return tc.SetKeepAlivePeriod(time.Duration(seconds) * time.Second)
				}
				return fmt.Errorf("not a TCP connection")
			},
			"SetNoDelay": func(noDelay bool) error {
				if tc, ok := conn.(*net.TCPConn); ok {
					return tc.SetNoDelay(noDelay)
				}
				return fmt.Errorf("not a TCP connection")
			},
			"SetLinger": func(sec int) error {
				if tc, ok := conn.(*net.TCPConn); ok {
					return tc.SetLinger(sec)
				}
				return fmt.Errorf("not a TCP connection")
			},
			"LocalAddr": func() string {
				return conn.LocalAddr().String()
			},
			"RemoteAddr": func() string {
				return conn.RemoteAddr().String()
			},
		}
	}

	jsCtx["Net"] = map[string]interface{}{
		// Dial connects to a TCP endpoint. Returns a connection object.
		"Dial": func(address string, timeoutMs int64) (map[string]interface{}, error) {
			if timeoutMs <= 0 {
				timeoutMs = 10000
			}
			r.Unlock()
			conn, err := net.DialTimeout("tcp", address, time.Duration(timeoutMs)*time.Millisecond)
			r.Lock()
			if err != nil {
				return nil, err
			}
			return wrapConn(conn), nil
		},
		// DialTLS connects with net.Dial (plain TCP, for TLS use fetch or custom).
		"DialTCP": func(address string, timeoutMs int64) (map[string]interface{}, error) {
			if timeoutMs <= 0 {
				timeoutMs = 10000
			}
			r.Unlock()
			conn, err := net.DialTimeout("tcp", address, time.Duration(timeoutMs)*time.Millisecond)
			r.Lock()
			if err != nil {
				return nil, err
			}
			return wrapConn(conn), nil
		},
		// DialUDP connects a UDP endpoint.
		"DialUDP": func(address string) (map[string]interface{}, error) {
			addr, err := net.ResolveUDPAddr("udp", address)
			if err != nil {
				return nil, err
			}
			r.Unlock()
			conn, err := net.DialUDP("udp", nil, addr)
			r.Lock()
			if err != nil {
				return nil, err
			}
			return wrapConn(conn), nil
		},
		// Listen starts a TCP listener (for server mode).
		"Listen": func(address string) (map[string]interface{}, error) {
			r.Unlock()
			ln, err := net.Listen("tcp", address)
			r.Lock()
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"Accept": func() (map[string]interface{}, error) {
					conn, err := ln.Accept()
					if err != nil {
						return nil, err
					}
					return wrapConn(conn), nil
				},
				"Close": func() error {
					return ln.Close()
				},
				"Addr": func() string {
					return ln.Addr().String()
				},
			}, nil
		},
		// RawSend sends raw bytes to a target over UDP.
		"RawSend": func(address string, data interface{}) error {
			b := gojaToBytes(data)
			if b == nil {
				return fmt.Errorf("invalid data type")
			}
			conn, err := net.Dial("udp", address)
			if err != nil {
				return err
			}
			defer conn.Close()
			_, err = conn.Write(b)
			return err
		},
		// DialRaw creates a raw IP socket with IP_HDRINCL
		"DialRaw": func(protocol string) (map[string]interface{}, error) {
			c, err := net.ListenPacket("ip4:"+protocol, "0.0.0.0")
			if err != nil {
				return nil, err
			}

			rawConn, err := ipv4.NewRawConn(c)
			if err != nil {
				c.Close()
				return nil, err
			}

			return map[string]interface{}{
				"Write": func(header map[string]interface{}, payload interface{}) error {
					h := &ipv4.Header{
						Version:  ipv4.Version,
						Len:      20,
						TotalLen: 20 + len(gojaToBytes(payload)),
						ID:       int(header["ID"].(int64)),
						FragOff:  0,
						TTL:      int(header["TTL"].(int64)),
						Protocol: int(header["Protocol"].(int64)),
						Src:      net.ParseIP(header["Src"].(string)),
						Dst:      net.ParseIP(header["Dst"].(string)),
					}

					p := gojaToBytes(payload)
					return rawConn.WriteTo(h, p, nil)
				},
				"Read": func() (map[string]interface{}, error) {
					b := make([]byte, 65535)
					h, p, _, err := rawConn.ReadFrom(b)
					if err != nil {
						return nil, err
					}
					return map[string]interface{}{
						"Header": map[string]interface{}{
							"Src":      h.Src.String(),
							"Dst":      h.Dst.String(),
							"Protocol": h.Protocol,
							"TTL":      h.TTL,
						},
						"Payload": p,
					}, nil
				},
				"Close": func() error {
					return rawConn.Close()
				},
			}, nil
		},
	}
}
