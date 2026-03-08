package sandbox

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"http-interperation/pkg/browser"
	"io"
	"strings"

	http "github.com/bogdanfinn/fhttp"

	"github.com/andybalholm/brotli"
)

// Response wraps the HTTP response
type Response struct {
	statusCode int
	body       []byte // Always stores decompressed content
	header     http.Header
	cookies    []*http.Cookie
	err        error
	bodyStream io.ReadCloser // For streaming responses
	localAddr  string        // Source address:port
	remoteAddr string        // Destination address:port
	profile    *browser.Profile
}

// decompressBody automatically decompresses response body based on Content-Encoding
func decompressBody(body []byte, encoding string) ([]byte, error) {
	encoding = strings.ToLower(strings.TrimSpace(encoding))

	switch encoding {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, err
		}
		defer reader.Close()
		return io.ReadAll(reader)

	case "deflate":
		reader := flate.NewReader(bytes.NewReader(body))
		defer reader.Close()
		return io.ReadAll(reader)

	case "br", "brotli":
		reader := brotli.NewReader(bytes.NewReader(body))
		return io.ReadAll(reader)

	default:
		// No compression or unknown encoding, return as-is
		return body, nil
	}
}

// Status returns the HTTP status code
func (r *Response) Status() int {
	return r.statusCode
}

// Body returns the response body as a string
func (r *Response) Body() string {
	return string(r.body)
}

// Header returns all response headers
func (r *Response) Header() http.Header {
	return r.header
}

// HeaderValue returns the value of a specific header key
func (r *Response) HeaderValue(key string) string {
	return r.header.Get(key)
}

// Json unmarshals the response body into the provided interface or returns a map
// Usage: var data MyStruct; res.Json(&data) OR res.Json() -> map[string]interface{}
func (r *Response) Json(v ...interface{}) interface{} {
	if len(v) > 0 {
		// If argument provided, unmarshal into it
		if err := json.Unmarshal(r.body, v[0]); err != nil {
			r.err = err
			return nil
		}
		return v[0]
	}
	// Default: return map/slice
	var result interface{}
	if err := json.Unmarshal(r.body, &result); err != nil {
		r.err = err
		return nil
	}
	return result
}

// Text returns the response body as a string (alias for Body)
func (r *Response) Text() string {
	return string(r.body)
}

// Bytes returns the response body as a byte slice
func (r *Response) Bytes() []byte {
	return r.body
}

// BodyStream returns the underlying response body stream
func (r *Response) BodyStream() io.ReadCloser {
	return r.bodyStream
}

// Error returns any error that occurred during request or processing
func (r *Response) Error() error {
	return r.err
}

// Close closes the underlying response body stream if it exists
func (r *Response) Close() {
	if r.bodyStream != nil {
		r.bodyStream.Close()
	}
}

// Cookies returns the parsed cookies
func (r *Response) Cookies() []*http.Cookie {
	return r.cookies
}

// LocalAddr returns the source address used for the connection
func (r *Response) LocalAddr() string {
	return r.localAddr
}

// RemoteAddr returns the destination address used for the connection
func (r *Response) RemoteAddr() string {
	return r.remoteAddr
}

// Profile returns the browser profile used for the request
func (r *Response) Profile() *browser.Profile {
	return r.profile
}
