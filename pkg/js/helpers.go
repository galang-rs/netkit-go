package js

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"strconv"

	"github.com/andybalholm/brotli"
)

// gojaToBytes converts various JS-compatible types to Go []byte.
// Used across multiple modules for type coercion.
func gojaToBytes(v interface{}) []byte {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return []byte(val)
	case []byte:
		return val
	case []interface{}:
		b := make([]byte, len(val))
		for i, x := range val {
			switch n := x.(type) {
			case int64:
				b[i] = byte(n)
			case float64:
				b[i] = byte(n)
			case int:
				b[i] = byte(n)
			}
		}
		return b
	}
	return nil
}

func decompressGzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func decompressDeflate(data []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()
	return io.ReadAll(r)
}

func decompressBrotli(data []byte) ([]byte, error) {
	r := brotli.NewReader(bytes.NewReader(data))
	return io.ReadAll(r)
}

// httpMethodPrefixes is pre-allocated once at package level to avoid per-call allocation.
var httpMethodPrefixes = [][]byte{
	[]byte("GET "), []byte("POST"), []byte("PUT "), []byte("DELE"),
	[]byte("HEAD"), []byte("OPTI"), []byte("PATC"), []byte("CONN"),
}

func IsHTTPRequest(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	for _, m := range httpMethodPrefixes {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}
	return false
}

func IsHTTPResponse(data []byte) bool {
	return bytes.HasPrefix(data, []byte("HTTP/"))
}

// Dechunk removes chunked transfer encoding from data.
func Dechunk(data []byte) []byte {
	var result []byte
	pos := 0
	for pos < len(data) {
		endLine := bytes.Index(data[pos:], []byte("\r\n"))
		if endLine == -1 {
			break
		}

		sizeHex := data[pos : pos+endLine]
		// Remove extensions if any (e.g., "1f;ext=val")
		if idx := bytes.IndexByte(sizeHex, ';'); idx >= 0 {
			sizeHex = sizeHex[:idx]
		}
		sizeStr := string(bytes.TrimSpace(sizeHex))

		size, err := strconv.ParseUint(sizeStr, 16, 64)
		if err != nil {
			break
		}

		if size == 0 {
			break
		}

		pos += endLine + 2 // move past size\r\n
		if pos+int(size) > len(data) {
			result = append(result, data[pos:]...)
			break
		}

		result = append(result, data[pos:pos+int(size)]...)
		pos += int(size) + 2 // skip chunk then \r\n
	}

	if len(result) == 0 {
		return data
	}
	return result
}
