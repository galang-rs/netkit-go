package js

import (
	"bytes"
	"strings"
)

// RegisterMIMEModule injects ctx.MIME into the JS context.
func RegisterMIMEModule(jsCtx map[string]interface{}) {
	jsCtx["MIME"] = map[string]interface{}{
		"Detect": func(data []byte) map[string]interface{} {
			return detectMime(data)
		},
		"GetInfo": func(mimeType string) map[string]interface{} {
			return getMimeInfo(mimeType)
		},
		"IsText": func(mimeType string) bool {
			info := getMimeInfo(mimeType)
			return info["category"] == "TEXT" || info["isText"] == true
		},
		"IsBinary": func(mimeType string) bool {
			info := getMimeInfo(mimeType)
			cat := info["category"].(string)
			return cat == "BINARY STRUCTURED" || cat == "APPLICATION" || cat == "IMAGE" || cat == "AUDIO" || cat == "VIDEO" || cat == "FONT"
		},
	}
}

func detectMime(data []byte) map[string]interface{} {
	if len(data) == 0 {
		return map[string]interface{}{"type": "application/octet-stream", "category": "UNKNOWN"}
	}

	// Check HTTP Headers first if it looks like HTTP
	if bytes.HasPrefix(data, []byte("HTTP/")) || bytes.Contains(data, []byte(" GET ")) || bytes.Contains(data, []byte(" POST ")) {
		ct := GetHTTPHeader(data)
		if ct != "" {
			// Strip parameters like ; charset=utf-8
			if idx := strings.IndexByte(ct, ';'); idx != -1 {
				ct = strings.TrimSpace(ct[:idx])
			}
			return getMimeInfo(strings.ToLower(ct))
		}
	}

	// Magic Bytes Detection
	if len(data) > 4 {
		// PNG: 89 50 4E 47
		if bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47}) {
			return getMimeInfo("image/png")
		}
		// JPEG: FF D8 FF
		if bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}) {
			return getMimeInfo("image/jpeg")
		}
		// GIF: GIF87a or GIF89a
		if bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a")) {
			return getMimeInfo("image/gif")
		}
		// PDF: %PDF-
		if bytes.HasPrefix(data, []byte("%PDF-")) {
			return getMimeInfo("application/pdf")
		}
		// ZIP: PK\x03\x04
		if bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x03, 0x04}) {
			return getMimeInfo("application/zip")
		}
		// GZIP: 1F 8B
		if bytes.HasPrefix(data, []byte{0x1F, 0x8B}) {
			return getMimeInfo("application/gzip")
		}
		// 7Z: 37 7A BC AF 27 1C
		if bytes.HasPrefix(data, []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}) {
			return getMimeInfo("application/x-7z-compressed")
		}
		// RAR: 52 61 72 21 1A 07
		if bytes.HasPrefix(data, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}) {
			return getMimeInfo("application/x-rar-compressed")
		}
		// WebP: RIFF .... WEBP
		if len(data) > 12 && bytes.HasPrefix(data, []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")) {
			return getMimeInfo("image/webp")
		}
		// Wasm: 00 61 73 6D
		if bytes.HasPrefix(data, []byte{0x00, 0x61, 0x73, 0x6D}) {
			return getMimeInfo("application/wasm")
		}
		// MsgPack: many patterns, but simple check for common ones
		if data[0] >= 0x80 && data[0] <= 0x8f || data[0] >= 0x90 && data[0] <= 0x9f || data[0] >= 0xa0 && data[0] <= 0xbf {
			// Likely MsgPack
			return getMimeInfo("application/msgpack")
		}
	}

	// Text Detection (heuristic)
	isText := true
	limit := 512
	if len(data) < limit {
		limit = len(data)
	}
	for i := 0; i < limit; i++ {
		c := data[i]
		if (c < 32 && c != 9 && c != 10 && c != 13) || c > 126 {
			isText = false
			break
		}
	}

	if isText {
		s := string(data[:limit])
		ls := strings.ToLower(s)
		if strings.Contains(ls, "<html") || strings.Contains(ls, "<!doctype html") {
			return getMimeInfo("text/html")
		}
		if strings.Contains(ls, "<?xml") || (strings.Contains(ls, "<") && strings.Contains(ls, ">")) {
			return getMimeInfo("text/xml")
		}
		if strings.Contains(ls, "{") && strings.Contains(ls, "\"") && strings.Contains(ls, ":") {
			return getMimeInfo("application/json")
		}
		if strings.Contains(ls, "---") && (strings.Contains(ls, "\n") || strings.Contains(ls, "\r")) {
			// Could be YAML or Markdown
			return getMimeInfo("text/plain")
		}
		return getMimeInfo("text/plain")
	}

	return getMimeInfo("application/octet-stream")
}

func getMimeInfo(mimeType string) map[string]interface{} {
	mapping := map[string]map[string]interface{}{
		"application/json":                  {"type": "application/json", "category": "APPLICATION", "isText": true},
		"application/ld+json":               {"type": "application/ld+json", "category": "APPLICATION", "isText": true},
		"application/xml":                   {"type": "application/xml", "category": "APPLICATION", "isText": true},
		"application/xhtml+xml":             {"type": "application/xhtml+xml", "category": "APPLICATION", "isText": true},
		"application/yaml":                  {"type": "application/yaml", "category": "APPLICATION", "isText": true},
		"application/pdf":                   {"type": "application/pdf", "category": "APPLICATION", "isText": false},
		"application/rtf":                   {"type": "application/rtf", "category": "APPLICATION", "isText": true},
		"application/sql":                   {"type": "application/sql", "category": "APPLICATION", "isText": true},
		"application/graphql":               {"type": "application/graphql", "category": "APPLICATION", "isText": true},
		"application/wasm":                  {"type": "application/wasm", "category": "APPLICATION", "isText": false},
		"application/octet-stream":          {"type": "application/octet-stream", "category": "APPLICATION", "isText": false},
		"application/x-www-form-urlencoded": {"type": "application/x-www-form-urlencoded", "category": "APPLICATION", "isText": true},
		"application/zip":                   {"type": "application/zip", "category": "APPLICATION", "isText": false},
		"application/x-7z-compressed":       {"type": "application/x-7z-compressed", "category": "APPLICATION", "isText": false},
		"application/x-rar-compressed":      {"type": "application/x-rar-compressed", "category": "APPLICATION", "isText": false},
		"application/gzip":                  {"type": "application/gzip", "category": "APPLICATION", "isText": false},
		"application/x-tar":                 {"type": "application/x-tar", "category": "APPLICATION", "isText": false},

		// RPC / PROTOBUF / BINARY API
		"application/protobuf":            {"type": "application/protobuf", "category": "RPC / PROTOBUF / BINARY API", "isText": false},
		"application/x-protobuf":          {"type": "application/x-protobuf", "category": "RPC / PROTOBUF / BINARY API", "isText": false},
		"application/grpc":                {"type": "application/grpc", "category": "RPC / PROTOBUF / BINARY API", "isText": false},
		"application/grpc+proto":          {"type": "application/grpc+proto", "category": "RPC / PROTOBUF / BINARY API", "isText": false},
		"application/grpc+json":           {"type": "application/grpc+json", "category": "RPC / PROTOBUF / BINARY API", "isText": true},
		"application/grpc-web":            {"type": "application/grpc-web", "category": "RPC / PROTOBUF / BINARY API", "isText": false},
		"application/grpc-web+proto":      {"type": "application/grpc-web+proto", "category": "RPC / PROTOBUF / BINARY API", "isText": false},
		"application/grpc-web+json":       {"type": "application/grpc-web+json", "category": "RPC / PROTOBUF / BINARY API", "isText": true},
		"application/connect+proto":       {"type": "application/connect+proto", "category": "RPC / PROTOBUF / BINARY API", "isText": false},
		"application/connect+json":        {"type": "application/connect+json", "category": "RPC / PROTOBUF / BINARY API", "isText": true},
		"application/vnd.google.protobuf": {"type": "application/vnd.google.protobuf", "category": "RPC / PROTOBUF / BINARY API", "isText": false},

		// BINARY STRUCTURED
		"application/msgpack":   {"type": "application/msgpack", "category": "BINARY STRUCTURED", "isText": false},
		"application/x-msgpack": {"type": "application/x-msgpack", "category": "BINARY STRUCTURED", "isText": false},
		"application/cbor":      {"type": "application/cbor", "category": "BINARY STRUCTURED", "isText": false},
		"application/bson":      {"type": "application/bson", "category": "BINARY STRUCTURED", "isText": false},
		"application/ubjson":    {"type": "application/ubjson", "category": "BINARY STRUCTURED", "isText": false},

		// STREAMING
		"application/stream+json": {"type": "application/stream+json", "category": "STREAMING", "isText": true},
		"application/x-ndjson":    {"type": "application/x-ndjson", "category": "STREAMING", "isText": true},
		"text/event-stream":       {"type": "text/event-stream", "category": "STREAMING", "isText": true},

		// TEXT
		"text/plain":      {"type": "text/plain", "category": "TEXT", "isText": true},
		"text/html":       {"type": "text/html", "category": "TEXT", "isText": true},
		"text/css":        {"type": "text/css", "category": "TEXT", "isText": true},
		"text/javascript": {"type": "text/javascript", "category": "TEXT", "isText": true},
		"text/xml":        {"type": "text/xml", "category": "TEXT", "isText": true},
		"text/csv":        {"type": "text/csv", "category": "TEXT", "isText": true},
		"text/markdown":   {"type": "text/markdown", "category": "TEXT", "isText": true},
		"text/vcard":      {"type": "text/vcard", "category": "TEXT", "isText": true},
		"text/calendar":   {"type": "text/calendar", "category": "TEXT", "isText": true},

		// MULTIPART
		"multipart/form-data":   {"type": "multipart/form-data", "category": "MULTIPART", "isText": false},
		"multipart/mixed":       {"type": "multipart/mixed", "category": "MULTIPART", "isText": false},
		"multipart/related":     {"type": "multipart/related", "category": "MULTIPART", "isText": false},
		"multipart/byteranges":  {"type": "multipart/byteranges", "category": "MULTIPART", "isText": false},
		"multipart/alternative": {"type": "multipart/alternative", "category": "MULTIPART", "isText": false},

		// IMAGE
		"image/png":     {"type": "image/png", "category": "IMAGE", "isText": false},
		"image/jpeg":    {"type": "image/jpeg", "category": "IMAGE", "isText": false},
		"image/jpg":     {"type": "image/jpg", "category": "IMAGE", "isText": false},
		"image/webp":    {"type": "image/webp", "category": "IMAGE", "isText": false},
		"image/gif":     {"type": "image/gif", "category": "IMAGE", "isText": false},
		"image/svg+xml": {"type": "image/svg+xml", "category": "IMAGE", "isText": true},
		"image/avif":    {"type": "image/avif", "category": "IMAGE", "isText": false},
		"image/bmp":     {"type": "image/bmp", "category": "IMAGE", "isText": false},
		"image/tiff":    {"type": "image/tiff", "category": "IMAGE", "isText": false},
		"image/x-icon":  {"type": "image/x-icon", "category": "IMAGE", "isText": false},

		// AUDIO
		"audio/mpeg": {"type": "audio/mpeg", "category": "AUDIO", "isText": false},
		"audio/wav":  {"type": "audio/wav", "category": "AUDIO", "isText": false},
		"audio/ogg":  {"type": "audio/ogg", "category": "AUDIO", "isText": false},
		"audio/webm": {"type": "audio/webm", "category": "AUDIO", "isText": false},
		"audio/aac":  {"type": "audio/aac", "category": "AUDIO", "isText": false},
		"audio/flac": {"type": "audio/flac", "category": "AUDIO", "isText": false},
		"audio/3gpp": {"type": "audio/3gpp", "category": "AUDIO", "isText": false},

		// VIDEO
		"video/mp4":        {"type": "video/mp4", "category": "VIDEO", "isText": false},
		"video/webm":       {"type": "video/webm", "category": "VIDEO", "isText": false},
		"video/ogg":        {"type": "video/ogg", "category": "VIDEO", "isText": false},
		"video/x-matroska": {"type": "video/x-matroska", "category": "VIDEO", "isText": false},
		"video/quicktime":  {"type": "video/quicktime", "category": "VIDEO", "isText": false},
		"video/3gpp":       {"type": "video/3gpp", "category": "VIDEO", "isText": false},
		"video/x-msvideo":  {"type": "video/x-msvideo", "category": "VIDEO", "isText": false},

		// FONT
		"font/woff":                     {"type": "font/woff", "category": "FONT", "isText": false},
		"font/woff2":                    {"type": "font/woff2", "category": "FONT", "isText": false},
		"font/ttf":                      {"type": "font/ttf", "category": "FONT", "isText": false},
		"font/otf":                      {"type": "font/otf", "category": "FONT", "isText": false},
		"application/vnd.ms-fontobject": {"type": "application/vnd.ms-fontobject", "category": "FONT", "isText": false},
	}

	if info, ok := mapping[mimeType]; ok {
		return info
	}
	return map[string]interface{}{"type": mimeType, "category": "OTHER", "isText": strings.HasPrefix(mimeType, "text/")}
}
