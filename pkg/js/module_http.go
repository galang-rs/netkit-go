package js

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
)

// RegisterHTTPModule injects ctx.HTTP into the JS context.
// Provides HTTP request/response parsing, header manipulation, cookie/query parsing.
// Functions available under ctx.HTTP:
// - ParseRequest(data): Structured request map
// - ParseResponse(data): Structured response map
// - BuildRequest/BuildResponse: Raw string constructor
// - ModifyHeader/RemoveHeader: Direct byte manipulation
func RegisterHTTPModule(jsCtx map[string]interface{}) {
	jsCtx["HTTP"] = map[string]interface{}{
		// ParseRequest parses raw HTTP request bytes into a structured object.
		"ParseRequest": func(data []byte) map[string]interface{} {
			return ParseHTTPRequest(data)
		},
		// ParseResponse parses raw HTTP response bytes into a structured object.
		"ParseResponse": func(data []byte) map[string]interface{} {
			return ParseHTTPResponse(data)
		},
		// ParseQueryString parses URL query string into key-value map.
		"ParseQueryString": func(qs string) map[string]interface{} {
			vals, err := url.ParseQuery(qs)
			if err != nil {
				return nil
			}
			result := make(map[string]interface{})
			for k, v := range vals {
				if len(v) == 1 {
					result[k] = v[0]
				} else {
					result[k] = v
				}
			}
			return result
		},
		// BuildQueryString builds a query string from key-value pairs.
		"BuildQueryString": func(params map[string]interface{}) string {
			vals := url.Values{}
			for k, v := range params {
				vals.Set(k, fmt.Sprintf("%v", v))
			}
			return vals.Encode()
		},
		// ParseCookies parses a Cookie header string.
		"ParseCookies": func(cookieHeader string) []map[string]interface{} {
			var cookies []map[string]interface{}
			for _, part := range strings.Split(cookieHeader, ";") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				idx := strings.IndexByte(part, '=')
				if idx < 0 {
					cookies = append(cookies, map[string]interface{}{
						"name":  part,
						"value": "",
					})
				} else {
					cookies = append(cookies, map[string]interface{}{
						"name":  part[:idx],
						"value": part[idx+1:],
					})
				}
			}
			return cookies
		},
		// ParseSetCookie parses a Set-Cookie header value.
		"ParseSetCookie": func(setCookie string) map[string]interface{} {
			result := map[string]interface{}{}
			parts := strings.Split(setCookie, ";")
			if len(parts) == 0 {
				return result
			}
			// First part is name=value
			first := strings.TrimSpace(parts[0])
			idx := strings.IndexByte(first, '=')
			if idx >= 0 {
				result["name"] = first[:idx]
				result["value"] = first[idx+1:]
			}
			for _, attr := range parts[1:] {
				attr = strings.TrimSpace(attr)
				al := strings.ToLower(attr)
				if strings.HasPrefix(al, "path=") {
					result["path"] = attr[5:]
				} else if strings.HasPrefix(al, "domain=") {
					result["domain"] = attr[7:]
				} else if strings.HasPrefix(al, "max-age=") {
					result["maxAge"] = attr[8:]
				} else if strings.HasPrefix(al, "expires=") {
					result["expires"] = attr[8:]
				} else if al == "secure" {
					result["secure"] = true
				} else if al == "httponly" {
					result["httpOnly"] = true
				} else if strings.HasPrefix(al, "samesite=") {
					result["sameSite"] = attr[9:]
				}
			}
			return result
		},
		// BuildHeaders creates raw HTTP header bytes from method/path/headers.
		"BuildRequest": func(method, path string, headers map[string]interface{}) string {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
			for k, v := range headers {
				sb.WriteString(fmt.Sprintf("%s: %v\r\n", k, v))
			}
			sb.WriteString("\r\n")
			return sb.String()
		},
		// BuildResponse creates a raw HTTP response.
		"BuildResponse": func(statusCode int, statusText string, headers map[string]interface{}, body string) string {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, statusText))
			for k, v := range headers {
				sb.WriteString(fmt.Sprintf("%s: %v\r\n", k, v))
			}
			if body != "" {
				sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
			}
			sb.WriteString("\r\n")
			sb.WriteString(body)
			return sb.String()
		},
		// ModifyHeader replaces or adds a header in raw HTTP data.
		"ModifyHeader": func(rawData []byte, headerName, headerValue string) []byte {
			return modifyHTTPHeader(rawData, headerName, headerValue)
		},
		// RemoveHeader removes a header from raw HTTP data.
		"RemoveHeader": func(rawData []byte, headerName string) []byte {
			return removeHTTPHeader(rawData, headerName)
		},
		// GetHeader extracts a header value from raw HTTP data.
		"GetHeader": func(rawData []byte, headerName string) string {
			return GetHTTPHeaderEx(rawData, headerName)
		},
		// ParseURL parses a URL into components.
		"ParseURL": func(rawURL string) (map[string]interface{}, error) {
			u, err := url.Parse(rawURL)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"scheme":   u.Scheme,
				"host":     u.Host,
				"hostname": u.Hostname(),
				"port":     u.Port(),
				"path":     u.Path,
				"query":    u.RawQuery,
				"fragment": u.Fragment,
				"userinfo": u.User.String(),
			}, nil
		},
	}
}

func ParseHTTPRequest(data []byte) map[string]interface{} {
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	sepLen := 4
	if headerEnd == -1 {
		headerEnd = bytes.Index(data, []byte("\n\n"))
		sepLen = 2
		if headerEnd == -1 {
			return nil
		}
	}

	headerPart := string(data[:headerEnd])
	lines := strings.Split(headerPart, "\n")
	if len(lines) == 0 {
		return nil
	}

	// Parse request line
	reqLine := strings.TrimRight(lines[0], "\r")
	parts := strings.SplitN(reqLine, " ", 3)
	if len(parts) < 2 {
		return nil
	}

	result := map[string]interface{}{
		"method":  parts[0],
		"path":    parts[1],
		"version": "",
	}
	if len(parts) > 2 {
		result["version"] = parts[2]
	}

	headers := make(map[string]interface{})
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		headers[key] = val
	}
	result["headers"] = headers

	body := data[headerEnd+sepLen:]
	result["body"] = body
	result["bodyString"] = string(body)

	// Extract URL query params
	if idx := strings.IndexByte(parts[1], '?'); idx >= 0 {
		qs := parts[1][idx+1:]
		vals, _ := url.ParseQuery(qs)
		qMap := make(map[string]interface{})
		for k, v := range vals {
			if len(v) == 1 {
				qMap[k] = v[0]
			} else {
				qMap[k] = v
			}
		}
		result["query"] = qMap
		result["pathOnly"] = parts[1][:idx]
	}

	return result
}

func ParseHTTPResponse(data []byte) map[string]interface{} {
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	sepLen := 4
	if headerEnd == -1 {
		headerEnd = bytes.Index(data, []byte("\n\n"))
		sepLen = 2
		if headerEnd == -1 {
			return nil
		}
	}

	headerPart := string(data[:headerEnd])
	lines := strings.Split(headerPart, "\n")
	if len(lines) == 0 {
		return nil
	}

	statusLine := strings.TrimRight(lines[0], "\r")
	parts := strings.SplitN(statusLine, " ", 3)

	result := map[string]interface{}{
		"version":    "",
		"statusCode": 0,
		"statusText": "",
	}
	if len(parts) >= 1 {
		result["version"] = parts[0]
	}
	if len(parts) >= 2 {
		var code int
		fmt.Sscanf(parts[1], "%d", &code)
		result["statusCode"] = code
	}
	if len(parts) >= 3 {
		result["statusText"] = parts[2]
	}

	headers := make(map[string]interface{})
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		headers[key] = val
	}
	result["headers"] = headers

	body := data[headerEnd+sepLen:]
	result["body"] = body
	result["bodyString"] = string(body)

	return result
}

func modifyHTTPHeader(data []byte, name, value string) []byte {
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return data
	}

	headerPart := string(data[:headerEnd])
	body := data[headerEnd:]

	lines := strings.Split(headerPart, "\r\n")
	found := false
	lName := strings.ToLower(name)
	for i, line := range lines {
		if i == 0 {
			continue // skip request/status line
		}
		idx := strings.IndexByte(line, ':')
		if idx >= 0 && strings.ToLower(strings.TrimSpace(line[:idx])) == lName {
			lines[i] = name + ": " + value
			found = true
			break
		}
	}
	if !found {
		// Insert before the last empty line
		lines = append(lines, name+": "+value)
	}

	result := []byte(strings.Join(lines, "\r\n"))
	result = append(result, body...)
	return result
}

func removeHTTPHeader(data []byte, name string) []byte {
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return data
	}

	headerPart := string(data[:headerEnd])
	body := data[headerEnd:]

	lines := strings.Split(headerPart, "\r\n")
	lName := strings.ToLower(name)
	var filtered []string
	for i, line := range lines {
		if i == 0 {
			filtered = append(filtered, line)
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx >= 0 && strings.ToLower(strings.TrimSpace(line[:idx])) == lName {
			continue
		}
		filtered = append(filtered, line)
	}

	result := []byte(strings.Join(filtered, "\r\n"))
	result = append(result, body...)
	return result
}

func GetHTTPHeader(data []byte) string {
	return GetHTTPHeaderEx(data, "Content-Type")
}

func GetHTTPHeaderEx(data []byte, name string) string {
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = len(data)
	}

	headerPart := string(data[:headerEnd])
	lName := strings.ToLower(name)
	for _, line := range strings.Split(headerPart, "\n") {
		line = strings.TrimRight(line, "\r")
		idx := strings.IndexByte(line, ':')
		if idx >= 0 && strings.ToLower(strings.TrimSpace(line[:idx])) == lName {
			return strings.TrimSpace(line[idx+1:])
		}
	}
	return ""
}
