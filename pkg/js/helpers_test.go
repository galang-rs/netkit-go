package js

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"testing"
)

// --- gojaToBytes ---

func TestGojaToBytes_Nil(t *testing.T) {
	result := gojaToBytes(nil)
	if result != nil {
		t.Error("nil input should return nil")
	}
}

func TestGojaToBytes_String(t *testing.T) {
	result := gojaToBytes("hello")
	if string(result) != "hello" {
		t.Errorf("Expected 'hello', got '%s'", string(result))
	}
}

func TestGojaToBytes_ByteSlice(t *testing.T) {
	input := []byte{0x01, 0x02, 0x03}
	result := gojaToBytes(input)
	if !bytes.Equal(result, input) {
		t.Errorf("Expected %v, got %v", input, result)
	}
}

func TestGojaToBytes_InterfaceSlice_Int64(t *testing.T) {
	input := []interface{}{int64(65), int64(66), int64(67)}
	result := gojaToBytes(input)
	if string(result) != "ABC" {
		t.Errorf("Expected 'ABC', got '%s'", string(result))
	}
}

func TestGojaToBytes_InterfaceSlice_Float64(t *testing.T) {
	input := []interface{}{float64(72), float64(73)}
	result := gojaToBytes(input)
	if string(result) != "HI" {
		t.Errorf("Expected 'HI', got '%s'", string(result))
	}
}

func TestGojaToBytes_InterfaceSlice_Int(t *testing.T) {
	input := []interface{}{int(88), int(89)}
	result := gojaToBytes(input)
	if string(result) != "XY" {
		t.Errorf("Expected 'XY', got '%s'", string(result))
	}
}

func TestGojaToBytes_UnsupportedType(t *testing.T) {
	result := gojaToBytes(12345)
	if result != nil {
		t.Error("Unsupported type should return nil")
	}
}

// --- IsHTTPRequest ---

func TestIsHTTPRequest_GET(t *testing.T) {
	if !IsHTTPRequest([]byte("GET /index.html HTTP/1.1\r\n")) {
		t.Error("GET request should be detected")
	}
}

func TestIsHTTPRequest_POST(t *testing.T) {
	if !IsHTTPRequest([]byte("POST /api HTTP/1.1\r\n")) {
		t.Error("POST request should be detected")
	}
}

func TestIsHTTPRequest_PUT(t *testing.T) {
	if !IsHTTPRequest([]byte("PUT /resource HTTP/1.1\r\n")) {
		t.Error("PUT request should be detected")
	}
}

func TestIsHTTPRequest_CONNECT(t *testing.T) {
	if !IsHTTPRequest([]byte("CONNECT example.com:443 HTTP/1.1\r\n")) {
		t.Error("CONNECT request should be detected")
	}
}

func TestIsHTTPRequest_NotHTTP(t *testing.T) {
	if IsHTTPRequest([]byte("Hello World")) {
		t.Error("Non-HTTP data should not be detected as request")
	}
}

func TestIsHTTPRequest_TooShort(t *testing.T) {
	if IsHTTPRequest([]byte("GE")) {
		t.Error("Data shorter than 4 bytes should not match")
	}
}

func TestIsHTTPRequest_Empty(t *testing.T) {
	if IsHTTPRequest(nil) {
		t.Error("nil should not match")
	}
	if IsHTTPRequest([]byte{}) {
		t.Error("empty should not match")
	}
}

func TestIsHTTPRequest_Binary(t *testing.T) {
	if IsHTTPRequest([]byte{0x16, 0x03, 0x01, 0x02, 0x00}) {
		t.Error("TLS handshake should not match HTTP")
	}
}

// --- IsHTTPResponse ---

func TestIsHTTPResponse_Valid(t *testing.T) {
	if !IsHTTPResponse([]byte("HTTP/1.1 200 OK\r\n")) {
		t.Error("HTTP response should be detected")
	}
}

func TestIsHTTPResponse_HTTP2(t *testing.T) {
	if !IsHTTPResponse([]byte("HTTP/2 200\r\n")) {
		t.Error("HTTP/2 response should be detected")
	}
}

func TestIsHTTPResponse_NotHTTP(t *testing.T) {
	if IsHTTPResponse([]byte("Not a response")) {
		t.Error("Non-HTTP data should not be detected as response")
	}
}

// --- Dechunk ---

func TestDechunk_Simple(t *testing.T) {
	chunked := []byte("5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n")
	result := Dechunk(chunked)
	if string(result) != "Hello World" {
		t.Errorf("Expected 'Hello World', got '%s'", string(result))
	}
}

func TestDechunk_SingleChunk(t *testing.T) {
	chunked := []byte("4\r\nTest\r\n0\r\n\r\n")
	result := Dechunk(chunked)
	if string(result) != "Test" {
		t.Errorf("Expected 'Test', got '%s'", string(result))
	}
}

func TestDechunk_HexSize(t *testing.T) {
	// 1f = 31 bytes
	data := bytes.Repeat([]byte("a"), 31)
	chunked := append([]byte("1f\r\n"), data...)
	chunked = append(chunked, []byte("\r\n0\r\n\r\n")...)
	result := Dechunk(chunked)
	if len(result) != 31 {
		t.Errorf("Expected 31 bytes, got %d", len(result))
	}
}

func TestDechunk_WithExtension(t *testing.T) {
	chunked := []byte("5;ext=val\r\nHello\r\n0\r\n\r\n")
	result := Dechunk(chunked)
	if string(result) != "Hello" {
		t.Errorf("Expected 'Hello', got '%s'", string(result))
	}
}

func TestDechunk_NotChunked(t *testing.T) {
	data := []byte("This is not chunked data")
	result := Dechunk(data)
	if !bytes.Equal(result, data) {
		t.Error("Non-chunked data should be returned as-is")
	}
}

func TestDechunk_Empty(t *testing.T) {
	result := Dechunk([]byte{})
	if len(result) != 0 {
		t.Error("Empty input should return empty")
	}
}

// --- Decompression ---

func TestDecompressGzip(t *testing.T) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte("compressed data"))
	w.Close()

	result, err := decompressGzip(buf.Bytes())
	if err != nil {
		t.Fatalf("decompressGzip failed: %v", err)
	}
	if string(result) != "compressed data" {
		t.Errorf("Expected 'compressed data', got '%s'", string(result))
	}
}

func TestDecompressGzip_Invalid(t *testing.T) {
	_, err := decompressGzip([]byte("not gzip"))
	if err == nil {
		t.Error("Invalid gzip data should return error")
	}
}

func TestDecompressDeflate(t *testing.T) {
	// Generate valid deflate data programmatically
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write([]byte("deflate test data"))
	w.Close()

	result, err := decompressDeflate(buf.Bytes())
	if err != nil {
		t.Fatalf("decompressDeflate failed: %v", err)
	}
	if string(result) != "deflate test data" {
		t.Errorf("Expected 'deflate test data', got '%s'", string(result))
	}
}

// --- Benchmarks ---

func BenchmarkIsHTTPRequest_Match(b *testing.B) {
	data := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsHTTPRequest(data)
	}
}

func BenchmarkIsHTTPRequest_NoMatch(b *testing.B) {
	data := []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsHTTPRequest(data)
	}
}

func BenchmarkGojaToBytes_String(b *testing.B) {
	s := "hello world this is a test payload for benchmark"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gojaToBytes(s)
	}
}

func BenchmarkGojaToBytes_ByteSlice(b *testing.B) {
	bs := []byte("hello world this is a test payload for benchmark")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gojaToBytes(bs)
	}
}

func BenchmarkDechunk(b *testing.B) {
	chunked := []byte("5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Dechunk(chunked)
	}
}

func BenchmarkDechunk_Large(b *testing.B) {
	// Build a 16KB chunked payload
	chunk := bytes.Repeat([]byte("x"), 4096)
	var chunked []byte
	for i := 0; i < 4; i++ {
		chunked = append(chunked, []byte("1000\r\n")...)
		chunked = append(chunked, chunk...)
		chunked = append(chunked, []byte("\r\n")...)
	}
	chunked = append(chunked, []byte("0\r\n\r\n")...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Dechunk(chunked)
	}
}
