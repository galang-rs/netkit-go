package js

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// fsMutex protects file system operations from concurrent access.
var fsMutex sync.RWMutex

// FSModuleConfig configures sandbox and limits for the FS module.
type FSModuleConfig struct {
	SandboxRoot string // If set, all paths must be under this root
	MaxFileSize int64  // Max bytes per write (0 = unlimited)
	AllowedExts []string
}

// RegisterFSModule injects ctx.FS into the JS context.
func RegisterFSModule(jsCtx map[string]interface{}, cfg *FSModuleConfig) {
	if cfg == nil {
		cfg = &FSModuleConfig{}
	}

	resolvePath := func(path string) (string, error) {
		cleanPath := path
		if strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\") {
			// Virtual root: treat as relative to SandboxRoot or CWD
			root := cfg.SandboxRoot
			if root == "" {
				root, _ = os.Getwd()
			}
			// Trim leading slashes to prevent Join from resolving to drive root on Windows
			cleanPath = filepath.Join(root, strings.TrimLeft(path, "/\\"))
		}

		abs, err := filepath.Abs(cleanPath)
		if err != nil {
			return "", err
		}
		// Path traversal protection
		if cfg.SandboxRoot != "" {
			root, _ := filepath.Abs(cfg.SandboxRoot)
			if !strings.HasPrefix(abs, root) {
				return "", fmt.Errorf("path %q escapes sandbox root %q", abs, root)
			}
		}
		return abs, nil
	}

	jsCtx["FS"] = map[string]interface{}{
		"SaveFile": func(path string, data []byte) error {
			abs, err := resolvePath(path)
			if err != nil {
				return err
			}
			if cfg.MaxFileSize > 0 && int64(len(data)) > cfg.MaxFileSize {
				return fmt.Errorf("file size %d exceeds limit %d", len(data), cfg.MaxFileSize)
			}
			fsMutex.Lock()
			defer fsMutex.Unlock()
			dir := filepath.Dir(abs)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				os.MkdirAll(dir, 0755)
			}
			return os.WriteFile(abs, data, 0644)
		},
		"SaveFileString": func(path string, data string) error {
			abs, err := resolvePath(path)
			if err != nil {
				return err
			}
			b := []byte(data)
			if cfg.MaxFileSize > 0 && int64(len(b)) > cfg.MaxFileSize {
				return fmt.Errorf("file size %d exceeds limit %d", len(b), cfg.MaxFileSize)
			}
			fsMutex.Lock()
			defer fsMutex.Unlock()
			dir := filepath.Dir(abs)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				os.MkdirAll(dir, 0755)
			}
			return os.WriteFile(abs, b, 0644)
		},
		"AppendFile": func(path string, data []byte) error {
			abs, err := resolvePath(path)
			if err != nil {
				return err
			}
			fsMutex.Lock()
			defer fsMutex.Unlock()
			dir := filepath.Dir(abs)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				os.MkdirAll(dir, 0755)
			}
			f, err := os.OpenFile(abs, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = f.Write(data)
			return err
		},
		"AppendFileString": func(path string, data string) error {
			abs, err := resolvePath(path)
			if err != nil {
				return err
			}
			fsMutex.Lock()
			defer fsMutex.Unlock()
			dir := filepath.Dir(abs)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				os.MkdirAll(dir, 0755)
			}
			f, err := os.OpenFile(abs, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = f.WriteString(data)
			return err
		},
		"MkdirAll": func(path string) error {
			abs, err := resolvePath(path)
			if err != nil {
				return err
			}
			fsMutex.Lock()
			defer fsMutex.Unlock()
			return os.MkdirAll(abs, 0755)
		},
		"Read": func(path string) ([]byte, error) {
			abs, err := resolvePath(path)
			if err != nil {
				return nil, err
			}
			fsMutex.RLock()
			defer fsMutex.RUnlock()
			return os.ReadFile(abs)
		},
		"ReadString": func(path string) (string, error) {
			abs, err := resolvePath(path)
			if err != nil {
				return "", err
			}
			fsMutex.RLock()
			defer fsMutex.RUnlock()
			b, err := os.ReadFile(abs)
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
		"Exists": func(path string) bool {
			abs, err := resolvePath(path)
			if err != nil {
				return false
			}
			fsMutex.RLock()
			defer fsMutex.RUnlock()
			_, err = os.Stat(abs)
			return err == nil
		},
		"Remove": func(path string) error {
			abs, err := resolvePath(path)
			if err != nil {
				return err
			}
			fsMutex.Lock()
			defer fsMutex.Unlock()
			return os.Remove(abs)
		},
		"ListDir": func(path string) ([]string, error) {
			abs, err := resolvePath(path)
			if err != nil {
				return nil, err
			}
			fsMutex.RLock()
			defer fsMutex.RUnlock()
			entries, err := os.ReadDir(abs)
			if err != nil {
				return nil, err
			}
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			return names, nil
		},
		"Stat": func(path string) (map[string]interface{}, error) {
			abs, err := resolvePath(path)
			if err != nil {
				return nil, err
			}
			fsMutex.RLock()
			defer fsMutex.RUnlock()
			info, err := os.Stat(abs)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"name":    info.Name(),
				"size":    info.Size(),
				"isDir":   info.IsDir(),
				"modTime": info.ModTime().UnixMilli(),
			}, nil
		},
		// Data() returns the historical list of packet/flow snapshots.
		"Data": func() []interface{} {
			historyMutex.RLock()
			defer historyMutex.RUnlock()
			return flowHistory
		},
		// SetDataLimit(limit) sets the maximum number of historical entries to store.
		"SetDataLimit": func(limit int) {
			if limit < 0 {
				limit = 0
			}
			historyMutex.Lock()
			defer historyMutex.Unlock()
			historyLimit = limit
			// Trim if current size exceeds new limit
			if len(flowHistory) > historyLimit {
				flowHistory = flowHistory[len(flowHistory)-historyLimit:]
			}
		},
		"Decompress": func(args ...interface{}) string {
			if len(args) == 0 {
				return ""
			}
			// First arg: data (string or byte array)
			var data []byte
			switch v := args[0].(type) {
			case string:
				data = []byte(v)
			case []byte:
				data = v
			case []interface{}:
				data = make([]byte, len(v))
				for i, x := range v {
					switch n := x.(type) {
					case int64:
						data[i] = byte(n)
					case float64:
						data[i] = byte(n)
					}
				}
			default:
				return ""
			}
			if len(data) == 0 {
				return ""
			}
			// Second arg: encoding (optional)
			if len(args) >= 2 {
				if enc, ok := args[1].(string); ok && enc != "" {
					enc = strings.ToLower(strings.TrimSpace(enc))
					// Try direct decompression first
					if decoded, err := decompressBody(data, enc); err == nil {
						return string(decoded)
					}
					// Try dechunking first, then decompress
					dechunked := Dechunk(data)
					if len(dechunked) > 0 && len(dechunked) != len(data) {
						if decoded, err := decompressBody(dechunked, enc); err == nil {
							return string(decoded)
						}
					}
					// Fallback to auto-detection
				}
			}
			return DecompressAuto(data)
		},
		// SetCache(key, value) stores a value in the global thread-safe cache.
		// These values persist across different packets and connection flows.
		"SetCache": func(key string, value interface{}) {
			globalCache.Store(key, value)
		},
		// GetCache(key) retrieves a value from the global cache.
		// Returns nil if the key is not found.
		"GetCache": func(key string) interface{} {
			if val, ok := globalCache.Load(key); ok {
				return val
			}
			return nil
		},
	}
}

var (
	flowHistory  []interface{}
	historyLimit = 100
	historyMutex sync.RWMutex
)

// RegisterHistory adds a flow snapshot to the global history.
func RegisterHistory(snapshot interface{}) {
	historyMutex.Lock()
	defer historyMutex.Unlock()

	if historyLimit <= 0 {
		return
	}

	flowHistory = append(flowHistory, snapshot)
	if len(flowHistory) > historyLimit {
		flowHistory = flowHistory[len(flowHistory)-historyLimit:]
	}
}

var globalCache sync.Map

// DecompressAuto attempts to decompress data, handling both HTTP and raw streams.
func DecompressAuto(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Heuristic: does it look like HTTP?
	if bytes.HasPrefix(data, []byte("HTTP/")) ||
		bytes.Contains(data[:min(len(data), 100)], []byte(" GET ")) ||
		bytes.Contains(data[:min(len(data), 100)], []byte(" POST ")) ||
		bytes.Contains(data[:min(len(data), 100)], []byte(" PUT ")) ||
		bytes.Contains(data[:min(len(data), 100)], []byte(" DELETE ")) ||
		bytes.Contains(data[:min(len(data), 100)], []byte(" PATCH ")) ||
		bytes.Contains(data[:min(len(data), 100)], []byte(" OPTIONS ")) ||
		bytes.Contains(data[:min(len(data), 100)], []byte(" HEAD ")) ||
		bytes.Contains(data[:min(len(data), 100)], []byte(" CONNECT ")) ||
		bytes.Contains(data[:min(len(data), 100)], []byte(" TRACE ")) {
		return decompressHTTP(data)
	}

	// If not HTTP, try raw decompression
	dec := decompressRaw(data)
	if len(dec) > 0 {
		return string(dec)
	}

	// Final fallback: return original data as string
	return string(data)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func decompressRaw(data []byte) []byte {
	if len(data) < 4 {
		return nil
	}

	// GZIP: 1F 8B
	if data[0] == 0x1f && data[1] == 0x8b {
		return decodeBytes(data, "gzip")
	}
	// ZLIB/Deflate: 78
	if data[0] == 0x78 {
		return decodeBytes(data, "deflate")
	}
	// Zstd: 28 B5 2F FD
	if bytes.HasPrefix(data, []byte{0x28, 0xB5, 0x2F, 0xFD}) {
		return decodeBytes(data, "zstd")
	}
	// Brotli: No simple magic byte, but we can try if it's very likely

	return nil
}

func decodeBytes(b []byte, enc string) []byte {
	if len(b) == 0 {
		return nil
	}
	buf := bytes.NewReader(b)
	switch enc {
	case "gzip":
		r, err := gzip.NewReader(buf)
		if err == nil {
			defer r.Close()
			out, _ := io.ReadAll(r)
			if len(out) > 0 {
				return out
			}
		}
	case "deflate":
		r, err := zlib.NewReader(buf)
		if err == nil {
			defer r.Close()
			out, _ := io.ReadAll(r)
			if len(out) > 0 {
				return out
			}
		}
		// Try raw flate
		r2 := flate.NewReader(bytes.NewReader(b))
		if r2 != nil {
			defer r2.Close()
			out, _ := io.ReadAll(r2)
			if len(out) > 0 {
				return out
			}
		}
	case "br":
		r := brotli.NewReader(buf)
		if r != nil {
			out, _ := io.ReadAll(r)
			if len(out) > 0 {
				return out
			}
		}
	case "zstd":
		r, err := zstd.NewReader(buf)
		if err == nil {
			defer r.Close()
			out, _ := io.ReadAll(r)
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

// decompressHTTP handles the full HTTP decompress logic.
func decompressHTTP(data []byte) string {
	var result strings.Builder
	offset := 0
	for offset < len(data) {
		headerEnd := bytes.Index(data[offset:], []byte("\r\n\r\n"))
		sepLen := 4
		if headerEnd == -1 {
			headerEnd = bytes.Index(data[offset:], []byte("\n\n"))
			if headerEnd == -1 {
				// No more headers found, write remainder as raw or decompress if magic
				remainder := data[offset:]
				rawDec := decompressRaw(remainder)
				if rawDec != nil {
					result.Write(rawDec)
				} else {
					result.Write(remainder)
				}
				break
			}
			sepLen = 2
		}
		headerEnd += offset

		rawHeaders := string(data[offset:headerEnd])
		contentLength := -1
		isChunked := false
		var encodings []string

		for _, line := range strings.Split(rawHeaders, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			idx := strings.IndexByte(line, ':')
			if idx <= 0 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])

			switch key {
			case "content-length":
				fmt.Sscanf(val, "%d", &contentLength)
			case "transfer-encoding":
				if strings.Contains(strings.ToLower(val), "chunked") {
					isChunked = true
				}
			case "content-encoding", "connect-content-encoding", "x-content-encoding":
				for _, e := range strings.Split(val, ",") {
					e = strings.TrimSpace(e)
					if e != "" {
						encodings = append(encodings, strings.ToLower(e))
					}
				}
			}
		}

		bodyStart := headerEnd + sepLen
		bodyEnd := len(data)

		if isChunked {
			cScan := bodyStart
			for cScan < len(data) {
				newlineIdx := bytes.IndexByte(data[cScan:], '\n')
				if newlineIdx == -1 {
					break
				}
				line := string(bytes.TrimSpace(data[cScan : cScan+newlineIdx]))
				cScan += newlineIdx + 1
				var size int
				if _, err := fmt.Sscanf(line, "%x", &size); err == nil {
					if size == 0 {
						if cScan+2 <= len(data) && data[cScan] == '\r' && data[cScan+1] == '\n' {
							bodyEnd = cScan + 2
						} else if cScan+1 <= len(data) && data[cScan] == '\n' {
							bodyEnd = cScan + 1
						} else {
							bodyEnd = cScan
						}
						break
					}
					cScan += size + 2
				}
			}
		} else if contentLength >= 0 {
			bodyEnd = bodyStart + contentLength
			if bodyEnd > len(data) {
				bodyEnd = len(data)
			}
		} else {
			lHeaders := strings.ToLower(rawHeaders)
			if strings.Contains(lHeaders, "304 not modified") || strings.Contains(lHeaders, "204 no content") {
				bodyEnd = bodyStart
			}
		}

		body := data[bodyStart:bodyEnd]

		if isChunked {
			var decodedBody []byte
			cOffset := 0
			for cOffset < len(body) {
				newlineIdx := bytes.IndexByte(body[cOffset:], '\n')
				if newlineIdx == -1 {
					break
				}
				line := string(bytes.TrimSpace(body[cOffset : cOffset+newlineIdx]))
				cOffset += newlineIdx + 1
				if line == "" {
					continue
				}
				var size int
				if _, err := fmt.Sscanf(line, "%x", &size); err != nil {
					break
				}
				if size == 0 {
					break
				}
				if cOffset+size > len(body) {
					decodedBody = append(decodedBody, body[cOffset:]...)
					cOffset = len(body)
					break
				}
				decodedBody = append(decodedBody, body[cOffset:cOffset+size]...)
				cOffset += size
				if cOffset < len(body) && body[cOffset] == '\r' {
					cOffset++
				}
				if cOffset < len(body) && body[cOffset] == '\n' {
					cOffset++
				}
			}
			body = decodedBody
		}

		for i := len(encodings) - 1; i >= 0; i-- {
			decoded := decodeBytes(body, encodings[i])
			if len(decoded) > 0 {
				body = decoded
			} else {
				// If a layer of decompression fails, keep what we have and stop
				break
			}
		}

		if len(encodings) == 0 && len(body) >= 4 {
			rawDec := decompressRaw(body)
			if len(rawDec) > 0 {
				body = rawDec
			}
		}

		var cleanHeaders []string
		for _, line := range strings.Split(rawHeaders, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			idx := strings.IndexByte(line, ':')
			if idx > 0 {
				key := strings.ToLower(strings.TrimSpace(line[:idx]))
				if key == "content-encoding" || key == "connect-content-encoding" || key == "x-content-encoding" || key == "transfer-encoding" || key == "content-length" {
					continue
				}
			}
			cleanHeaders = append(cleanHeaders, strings.TrimRight(line, "\r"))
		}

		result.WriteString(strings.Join(cleanHeaders, "\r\n"))
		result.Write([]byte("\r\n\r\n"))
		result.Write(body)

		offset = bodyEnd
	}

	return result.String()
}
