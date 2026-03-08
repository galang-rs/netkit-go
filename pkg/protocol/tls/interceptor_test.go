package tls

import (
	ctls "crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
)

type mockEngine struct {
	engine.Engine
}

func TestTLSInterceptor_ALPN(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	ti := NewTLSInterceptor(ca, &mockEngine{})
	ti.Verbose = true

	tests := []struct {
		name         string
		hostname     string
		clientProtos []string
		expectedALPN string
		forceHTTP11  bool
	}{
		{
			name:         "Google Domain without ALPN",
			hostname:     "daily-cloudcode-pa.googleapis.com",
			clientProtos: nil,
			expectedALPN: "",
		},
		{
			name:         "Google Domain with h2",
			hostname:     "daily-cloudcode-pa.googleapis.com",
			clientProtos: []string{"h2", "http/1.1"},
			expectedALPN: "h2",
		},
		{
			name:         "Google Domain with only http/1.1",
			hostname:     "daily-cloudcode-pa.googleapis.com",
			clientProtos: []string{"http/1.1"},
			expectedALPN: "http/1.1",
		},
		{
			name:         "Non-Google Domain without ALPN",
			hostname:     "example.com",
			clientProtos: nil,
			expectedALPN: "",
		},
		{
			name:         "Non-Google Domain with ALPN",
			hostname:     "example.com",
			clientProtos: []string{"h2", "http/1.1"},
			expectedALPN: "h2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ti.ForceHTTP11 = tt.forceHTTP11

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to listen: %v", err)
			}
			defer ln.Close()

			errCh := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					errCh <- err
					return
				}
				defer conn.Close()

				// The Intercept method will do the handshake.
				// We pass nil for protos in Intercept here as it represents what we'd normally get from SNI listener.
				// In reality, SNI listener peeks ALPN.
				_, err = ti.Intercept(conn, tt.hostname, tt.clientProtos)
				errCh <- err
			}()

			// Client side
			dialer := &net.Dialer{Timeout: 2 * time.Second}
			conn, err := dialer.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("failed to dial: %v", err)
			}
			defer conn.Close()

			conf := &ctls.Config{
				ServerName:         tt.hostname,
				NextProtos:         tt.clientProtos,
				InsecureSkipVerify: true,
			}

			tlsConn := ctls.Client(conn, conf)
			err = tlsConn.Handshake()
			if err != nil {
				t.Fatalf("client handshake failed: %v", err)
			}

			cs := tlsConn.ConnectionState()
			if cs.NegotiatedProtocol != tt.expectedALPN {
				t.Errorf("expected ALPN %q, got %q", tt.expectedALPN, cs.NegotiatedProtocol)
			}

			err = <-errCh
			if err != nil {
				t.Errorf("server Intercept failed: %v", err)
			}
		})
	}
}
