package network

import (
	http "github.com/bogdanfinn/fhttp"
)

// UserAgentTransport wraps a RoundTripper and adds complete browser fingerprint headers
type UserAgentTransport struct {
	Base      http.RoundTripper
	UserAgent string

	// HTTP Fingerprint headers
	Accept          string
	AcceptLanguage  string
	AcceptEncoding  string
	SecFetchDest    string
	SecFetchMode    string
	SecFetchSite    string
	SecFetchUser    string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
	HeaderOrder     []string
}

// RoundTrip implements http.RoundTripper
func (t *UserAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Apply all browser fingerprint headers with proper ordering
	ApplyBrowserHeaders(
		req,
		t.UserAgent,
		t.AcceptLanguage,
		t.AcceptEncoding,
		t.Accept,
		t.SecFetchDest,
		t.SecFetchMode,
		t.SecFetchSite,
		t.SecFetchUser,
		t.SecChUa,
		t.SecChUaMobile,
		t.SecChUaPlatform,
		t.HeaderOrder,
	)

	return t.Base.RoundTrip(req)
}
