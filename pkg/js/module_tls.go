package js

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/protocol/tls"

	"github.com/dop251/goja"
)

// TLSTools provides utility functions for JS to manipulate TLS.
type TLSTools struct {
	vm *goja.Runtime
}

func (t *TLSTools) ParseClientHello(data []byte) (interface{}, error) {
	ch, err := tls.ParseClientHello(data)
	if err != nil {
		return nil, err
	}
	return ch, nil
}

func (t *TLSTools) ReconstructClientHello(ch *tls.ClientHello) []byte {
	return ch.Reconstruct()
}

// RegisterTLSModule injects ctx.TLS into the JS context.
func RegisterTLSModule(r *Runtime, jsCtx map[string]interface{}, eng engine.Engine) {
	vm := r.vm
	tools := &TLSTools{vm: vm}

	jsCtx["TLS"] = map[string]interface{}{
		"ParseClientHello": func(data []byte) (interface{}, error) {
			return tools.ParseClientHello(data)
		},
		"ReconstructClientHello": func(ch *tls.ClientHello) []byte {
			return tools.ReconstructClientHello(ch)
		},
		// ExtractSNI extracts the SNI from a TLS ClientHello payload.
		"ExtractSNI": func(data []byte) string {
			return extractSNI(data)
		},
		// ExtractALPN extracts the ALPN protocols from a TLS ClientHello.
		"ExtractALPN": func(data []byte) []string {
			return extractALPN(data)
		},
		// GetVersion returns the TLS version string from the record layer.
		"GetVersion": func(data []byte) string {
			if len(data) < 3 {
				return "unknown"
			}
			major := data[1]
			minor := data[2]
			switch {
			case major == 3 && minor == 0:
				return "SSL 3.0"
			case major == 3 && minor == 1:
				return "TLS 1.0"
			case major == 3 && minor == 2:
				return "TLS 1.1"
			case major == 3 && minor == 3:
				return "TLS 1.2"
			case major == 3 && minor == 4:
				return "TLS 1.3"
			default:
				return fmt.Sprintf("unknown (%d.%d)", major, minor)
			}
		},
		// IsTLS checks if payload is a TLS record.
		"IsTLS": func(data []byte) bool {
			return IsTLSHandshake(data)
		},
		// IsClientHello checks for ClientHello specifically.
		"IsClientHello": func(data []byte) bool {
			return IsTLSClientHello(data)
		},
		// InstallCA installs the root CA to the Windows trust store.
		"InstallCA": func() (bool, error) {
			if m, ok := eng.(interface{ InstallCA() error }); ok {
				err := m.InstallCA()
				return err == nil, err
			}
			return false, fmt.Errorf("engine does not support CA installation")
		},
		// IsServerHello checks for ServerHello.
		"IsServerHello": func(data []byte) bool {
			if len(data) < 6 {
				return false
			}
			return data[0] == 0x16 && data[5] == 0x02
		},
		// RewriteSNI replaces the SNI in a TLS ClientHello payload.
		"RewriteSNI": func(data []byte, newSNI string) []byte {
			return rewriteSNI(data, newSNI)
		},
		// GetRecordType returns the TLS record content type.
		"GetRecordType": func(data []byte) string {
			if len(data) < 1 {
				return "unknown"
			}
			switch data[0] {
			case 20:
				return "ChangeCipherSpec"
			case 21:
				return "Alert"
			case 22:
				return "Handshake"
			case 23:
				return "Application"
			default:
				return fmt.Sprintf("unknown (%d)", data[0])
			}
		},
		// GetHandshakeType returns the TLS handshake message type.
		"GetHandshakeType": func(data []byte) string {
			if len(data) < 6 {
				return "unknown"
			}
			if data[0] != 0x16 {
				return "not handshake"
			}
			switch data[5] {
			case 0:
				return "HelloRequest"
			case 1:
				return "ClientHello"
			case 2:
				return "ServerHello"
			case 4:
				return "NewSessionTicket"
			case 11:
				return "Certificate"
			case 12:
				return "ServerKeyExchange"
			case 13:
				return "CertificateRequest"
			case 14:
				return "ServerHelloDone"
			case 15:
				return "CertificateVerify"
			case 16:
				return "ClientKeyExchange"
			case 20:
				return "Finished"
			default:
				return fmt.Sprintf("unknown (%d)", data[5])
			}
		},
	}
}

// RegisterTLSAccountModule injects ctx.Account TLS callbacks.
func RegisterTLSAccountModule(jsCtx map[string]interface{}, account AccountSaver) {
	if account == nil {
		return
	}
	jsCtx["Account"] = map[string]interface{}{
		"SaveTLS": func(ja3, ja4, ja3s, ja4s, akamai, cloudflare string) {
			account.SaveTLS(ja3, ja4, ja3s, ja4s, akamai, cloudflare)
		},
		"SaveCookie": func(name, value string) {
			account.SaveCookie(name, value)
		},
		"SaveToken": func(token string) {
			account.SaveToken(token)
		},
		"SaveUA": func(ua string) {
			account.SaveUA(ua)
		},
		"ComputeClientHello": func(raw []interface{}) {
			b := jsArrayToBytes(raw)
			account.ComputeClientHello(b)
		},
		"ComputeServerHello": func(raw []interface{}) {
			b := jsArrayToBytes(raw)
			account.ComputeServerHello(b)
		},
	}
}

func jsArrayToBytes(raw []interface{}) []byte {
	b := make([]byte, len(raw))
	for i, v := range raw {
		switch n := v.(type) {
		case int64:
			b[i] = byte(n)
		case float64:
			b[i] = byte(n)
		}
	}
	return b
}

func extractSNI(data []byte) string {
	// Minimal TLS ClientHello SNI extraction
	if len(data) < 44 {
		return ""
	}
	if data[0] != 0x16 || data[5] != 0x01 {
		return ""
	}

	// Skip record header (5) + handshake header (4) + version (2) + random (32) = 43
	offset := 43

	// Session ID length
	if offset >= len(data) {
		return ""
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Cipher suites length
	if offset+2 > len(data) {
		return ""
	}
	cipherLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2 + cipherLen

	// Compression methods length
	if offset >= len(data) {
		return ""
	}
	compLen := int(data[offset])
	offset += 1 + compLen

	// Extensions length
	if offset+2 > len(data) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	extEnd := offset + extLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[offset:])
		extDataLen := int(binary.BigEndian.Uint16(data[offset+2:]))
		offset += 4

		if extType == 0 { // SNI extension
			if offset+5 <= extEnd {
				// Skip SNI list length (2) + type (1) + name length (2)
				nameLen := int(binary.BigEndian.Uint16(data[offset+3:]))
				nameStart := offset + 5
				if nameStart+nameLen <= extEnd {
					return string(data[nameStart : nameStart+nameLen])
				}
			}
		}
		offset += extDataLen
	}

	return ""
}

func extractALPN(data []byte) []string {
	if len(data) < 44 || data[0] != 0x16 || data[5] != 0x01 {
		return nil
	}

	offset := 43
	if offset >= len(data) {
		return nil
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	if offset+2 > len(data) {
		return nil
	}
	cipherLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2 + cipherLen

	if offset >= len(data) {
		return nil
	}
	compLen := int(data[offset])
	offset += 1 + compLen

	if offset+2 > len(data) {
		return nil
	}
	extLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	extEnd := offset + extLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[offset:])
		extDataLen := int(binary.BigEndian.Uint16(data[offset+2:]))
		offset += 4

		if extType == 16 { // ALPN extension
			if offset+2 <= extEnd {
				alpnListLen := int(binary.BigEndian.Uint16(data[offset:]))
				alpnOffset := offset + 2
				alpnEnd := alpnOffset + alpnListLen
				if alpnEnd > extEnd {
					alpnEnd = extEnd
				}
				var protocols []string
				for alpnOffset < alpnEnd {
					protoLen := int(data[alpnOffset])
					alpnOffset++
					if alpnOffset+protoLen > alpnEnd {
						break
					}
					protocols = append(protocols, string(data[alpnOffset:alpnOffset+protoLen]))
					alpnOffset += protoLen
				}
				return protocols
			}
		}
		offset += extDataLen
	}
	return nil
}

func rewriteSNI(data []byte, newSNI string) []byte {
	oldSNI := extractSNI(data)
	if oldSNI == "" {
		return data
	}

	// Simple byte replacement: find old SNI bytes and replace
	oldBytes := []byte(oldSNI)
	newBytes := []byte(newSNI)

	// Find the SNI in the payload
	idx := -1
	for i := 0; i+len(oldBytes) <= len(data); i++ {
		match := true
		for j := 0; j < len(oldBytes); j++ {
			if data[i+j] != oldBytes[j] {
				match = false
				break
			}
		}
		if match {
			idx = i
			break
		}
	}

	if idx < 0 {
		return data
	}

	if len(newBytes) == len(oldBytes) {
		// Same length: simple replace
		result := make([]byte, len(data))
		copy(result, data)
		copy(result[idx:], newBytes)
		return result
	}

	// Different length: rebuild (simplified)
	result := make([]byte, 0, len(data)-len(oldBytes)+len(newBytes))
	result = append(result, data[:idx]...)
	result = append(result, newBytes...)
	result = append(result, data[idx+len(oldBytes):]...)
	return result
}

// Needed for the unused import suppression
var _ = engine.ActionContinue
var _ = strings.ToLower
var _ = net.IPv4zero
