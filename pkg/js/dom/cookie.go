package dom

import (
	"net/url"
	"strings"
	"sync"
	"time"
)

// Cookie represents a single HTTP cookie.
type Cookie struct {
	Name     string
	Value    string
	Domain   string
	Path     string
	Expires  time.Time
	MaxAge   int
	Secure   bool
	HTTPOnly bool
	SameSite string
}

// CookieJar is a thread-safe in-memory cookie store.
type CookieJar struct {
	mu      sync.RWMutex
	cookies []*Cookie
}

// NewCookieJar creates an empty cookie jar.
func NewCookieJar() *CookieJar {
	return &CookieJar{
		cookies: make([]*Cookie, 0),
	}
}

// Set adds or updates a cookie.
func (j *CookieJar) Set(name, value string, opts map[string]interface{}) {
	j.mu.Lock()
	defer j.mu.Unlock()

	c := &Cookie{
		Name:  name,
		Value: value,
		Path:  "/",
	}

	if opts != nil {
		if d, ok := opts["domain"].(string); ok {
			c.Domain = d
		}
		if p, ok := opts["path"].(string); ok {
			c.Path = p
		}
		if s, ok := opts["secure"].(bool); ok {
			c.Secure = s
		}
		if h, ok := opts["httpOnly"].(bool); ok {
			c.HTTPOnly = h
		}
		if ss, ok := opts["sameSite"].(string); ok {
			c.SameSite = ss
		}
		if ma, ok := opts["maxAge"].(int64); ok {
			c.MaxAge = int(ma)
		} else if ma, ok := opts["maxAge"].(int); ok {
			c.MaxAge = ma
		} else if ma, ok := opts["maxAge"].(float64); ok {
			c.MaxAge = int(ma)
		}
		if exp, ok := opts["expires"].(string); ok {
			if t, err := time.Parse(time.RFC1123, exp); err == nil {
				c.Expires = t
			}
		}
	}

	// Replace existing cookie with same name+domain+path
	for i, existing := range j.cookies {
		if existing.Name == name && existing.Domain == c.Domain && existing.Path == c.Path {
			j.cookies[i] = c
			return
		}
	}
	j.cookies = append(j.cookies, c)
}

// Get returns the value of a cookie by name, or empty string.
func (j *CookieJar) Get(name string) string {
	j.mu.RLock()
	defer j.mu.RUnlock()
	for _, c := range j.cookies {
		if c.Name == name && !j.isExpired(c) {
			return c.Value
		}
	}
	return ""
}

// GetAll returns all non-expired cookies.
func (j *CookieJar) GetAll() []*Cookie {
	j.mu.RLock()
	defer j.mu.RUnlock()
	var result []*Cookie
	for _, c := range j.cookies {
		if !j.isExpired(c) {
			result = append(result, c)
		}
	}
	return result
}

// Delete removes a cookie by name.
func (j *CookieJar) Delete(name string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := len(j.cookies) - 1; i >= 0; i-- {
		if j.cookies[i].Name == name {
			j.cookies = append(j.cookies[:i], j.cookies[i+1:]...)
		}
	}
}

// Clear removes all cookies.
func (j *CookieJar) Clear() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = j.cookies[:0]
}

// String returns cookies formatted as document.cookie string.
func (j *CookieJar) String() string {
	j.mu.RLock()
	defer j.mu.RUnlock()
	var parts []string
	for _, c := range j.cookies {
		if !j.isExpired(c) {
			parts = append(parts, c.Name+"="+c.Value)
		}
	}
	return strings.Join(parts, "; ")
}

// ForURL returns cookies applicable to the given URL.
func (j *CookieJar) ForURL(rawURL string) []*Cookie {
	j.mu.RLock()
	defer j.mu.RUnlock()

	u, err := url.Parse(rawURL)
	if err != nil {
		return j.GetAll()
	}

	var result []*Cookie
	for _, c := range j.cookies {
		if j.isExpired(c) {
			continue
		}
		// Domain match
		if c.Domain != "" && !domainMatch(u.Hostname(), c.Domain) {
			continue
		}
		// Path match
		if c.Path != "" && !strings.HasPrefix(u.Path, c.Path) {
			continue
		}
		// Secure check
		if c.Secure && u.Scheme != "https" {
			continue
		}
		result = append(result, c)
	}
	return result
}

// SetFromHeader parses a Set-Cookie header value and adds the cookie.
func (j *CookieJar) SetFromHeader(header string) {
	parts := strings.Split(header, ";")
	if len(parts) == 0 {
		return
	}

	// First part is name=value
	nv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
	if len(nv) < 2 {
		return
	}

	opts := map[string]interface{}{}
	for _, part := range parts[1:] {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := ""
		if len(kv) == 2 {
			val = strings.TrimSpace(kv[1])
		}
		switch key {
		case "domain":
			opts["domain"] = val
		case "path":
			opts["path"] = val
		case "secure":
			opts["secure"] = true
		case "httponly":
			opts["httpOnly"] = true
		case "samesite":
			opts["sameSite"] = val
		case "max-age":
			opts["maxAge"] = val
		case "expires":
			opts["expires"] = val
		}
	}

	j.Set(strings.TrimSpace(nv[0]), strings.TrimSpace(nv[1]), opts)
}

// CookieHeader returns cookies formatted as a Cookie request header.
func (j *CookieJar) CookieHeader(rawURL string) string {
	cookies := j.ForURL(rawURL)
	var parts []string
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

func (j *CookieJar) isExpired(c *Cookie) bool {
	if c.MaxAge < 0 {
		return true
	}
	if !c.Expires.IsZero() && time.Now().After(c.Expires) {
		return true
	}
	return false
}

func domainMatch(host, domain string) bool {
	domain = strings.TrimPrefix(domain, ".")
	return host == domain || strings.HasSuffix(host, "."+domain)
}
