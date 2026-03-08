package tls

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// CalculateJA4 computes the JA4 fingerprint from a ClientHello
func CalculateJA4(ch *ClientHello) string {
	// JA4 is composed of 3 parts: a_b_c
	// a: protocol_version + sn_flag + num_ciphers + num_extensions + first_alpn
	// b: truncated sha256 of sorted extensions
	// c: truncated sha256 of sorted ciphers

	// Part A
	// Detect actual TLS version: check supported_versions extension (type 43) for 0x0304 = TLS 1.3
	actualVersion := ch.Version
	for _, ext := range ch.Extensions {
		if ext.Type == 43 && len(ext.Data) >= 3 { // supported_versions
			listLen := int(ext.Data[0])
			for i := 1; i+1 < 1+listLen && i+1 < len(ext.Data); i += 2 {
				v := (uint16(ext.Data[i]) << 8) | uint16(ext.Data[i+1])
				if v == 0x0304 { // TLS 1.3
					actualVersion = 0x0304
					break
				}
			}
		}
	}

	var tlsVer string
	switch actualVersion {
	case 0x0304:
		tlsVer = "13"
	case 0x0303:
		tlsVer = "12"
	case 0x0302:
		tlsVer = "11"
	case 0x0301:
		tlsVer = "10"
	default:
		tlsVer = fmt.Sprintf("%04x", actualVersion)
	}

	sniFlag := "i"
	if ch.SNI != "" {
		sniFlag = "d"
	}

	numCiphers := fmt.Sprintf("%02d", len(ch.CipherSuites))
	if len(ch.CipherSuites) > 99 {
		numCiphers = "99"
	}

	numExts := fmt.Sprintf("%02d", len(ch.Extensions))
	if len(ch.Extensions) > 99 {
		numExts = "99"
	}

	alpn := "00"
	for _, ext := range ch.Extensions {
		if ext.Type == 16 { // ALPN
			if len(ext.Data) > 5 {
				// Simplified: take first 2 chars of first ALPN
				alpn = string(ext.Data[5:7])
			}
		}
	}

	partA := fmt.Sprintf("t%s%s%s%s%s", tlsVer, sniFlag, numCiphers, numExts, alpn)

	// Part B (Extensions)
	var extTypes []string
	for _, ext := range ch.Extensions {
		// Filter out GREASE and SNI/ALPN for part B sorting usually
		if !isGrease(ext.Type) && ext.Type != 0 && ext.Type != 16 {
			extTypes = append(extTypes, fmt.Sprintf("%04x", ext.Type))
		}
	}
	sort.Strings(extTypes)
	hashB := sha256.Sum256([]byte(strings.Join(extTypes, ",")))
	partB := hex.EncodeToString(hashB[:6])

	// Part C (Ciphers)
	var cipherIDs []string
	for _, c := range ch.CipherSuites {
		if !isGrease(c) {
			cipherIDs = append(cipherIDs, fmt.Sprintf("%04x", c))
		}
	}
	sort.Strings(cipherIDs)
	hashC := sha256.Sum256([]byte(strings.Join(cipherIDs, ",")))
	partC := hex.EncodeToString(hashC[:6])

	return fmt.Sprintf("%s_%s_%s", partA, partB, partC)
}

// CalculateAkamaiFingerprint computes the Akamai HTTP/2 or TLS fingerprint
func CalculateAkamaiFingerprint(ch *ClientHello) string {
	// Implementation based on Akamai's field ordering
	var parts []string
	// 1. TLS Version
	parts = append(parts, fmt.Sprintf("%d", ch.Version))

	// 2. Ciphers (comma separated)
	var ciphers []string
	for _, c := range ch.CipherSuites {
		ciphers = append(ciphers, fmt.Sprintf("%d", c))
	}
	parts = append(parts, strings.Join(ciphers, ","))

	// 3. Extensions
	var exts []string
	for _, ext := range ch.Extensions {
		exts = append(exts, fmt.Sprintf("%d", ext.Type))
	}
	parts = append(parts, strings.Join(exts, ","))

	// 4. Curves
	var curves []string
	for _, ext := range ch.Extensions {
		if ext.Type == 10 { // supported_groups
			if len(ext.Data) >= 2 {
				// skip length
				for i := 2; i < len(ext.Data); i += 2 {
					curves = append(curves, fmt.Sprintf("%d", (uint16(ext.Data[i])<<8)|uint16(ext.Data[i+1])))
				}
			}
		}
	}
	parts = append(parts, strings.Join(curves, ","))

	// 5. Formats
	var formats []string
	for _, ext := range ch.Extensions {
		if ext.Type == 11 { // point formats
			if len(ext.Data) >= 1 {
				for i := 1; i < len(ext.Data); i++ {
					formats = append(formats, fmt.Sprintf("%d", ext.Data[i]))
				}
			}
		}
	}
	parts = append(parts, strings.Join(formats, ","))

	return strings.Join(parts, "|")
}

// CalculateJA3S computes the JA3S (Server Hello) fingerprint
func CalculateJA3S(data []byte) (string, string) {
	// Simplified ServerHello parsing for JA3S
	if len(data) < 44 || data[0] != 22 || data[5] != 2 { // Handshake=22, ServerHello=2
		return "", ""
	}

	offset := 9
	version := (uint16(data[offset]) << 8) | uint16(data[offset+1])
	offset += 34 // version + random

	// Session ID
	sessLen := int(data[offset])
	offset += 1 + sessLen

	// Selected Cipher
	cipher := (uint16(data[offset]) << 8) | uint16(data[offset+1])
	offset += 2

	// Compression
	offset += 1

	// Extensions
	var exts []string
	if offset+2 <= len(data) {
		extLen := int((uint16(data[offset]) << 8) | uint16(data[offset+1]))
		offset += 2
		end := offset + extLen
		for offset+4 <= end {
			extType := (uint16(data[offset]) << 8) | uint16(data[offset+1])
			extDataLen := int((uint16(data[offset+2]) << 8) | uint16(data[offset+3]))
			exts = append(exts, fmt.Sprintf("%d", extType))
			offset += 4 + extDataLen
		}
	}

	ja3s := fmt.Sprintf("%d,%d,%s", version, cipher, strings.Join(exts, "-"))
	hash := md5.Sum([]byte(ja3s))
	return ja3s, hex.EncodeToString(hash[:])
}

// CalculateJA4S computes the JA4S (Server Hello) fingerprint
func CalculateJA4S(data []byte) string {
	if len(data) < 44 || data[0] != 22 || data[5] != 2 {
		return ""
	}

	offset := 9
	version := (uint16(data[offset]) << 8) | uint16(data[offset+1])
	verStr := fmt.Sprintf("%04x", version)
	if version == 0x0303 {
		verStr = "13"
	}
	offset += 34 // version + random

	// Session ID
	sessLen := int(data[offset])
	offset += 1 + sessLen

	// Selected Cipher
	// cipher := (uint16(data[offset]) << 8) | uint16(data[offset+1])
	offset += 2

	// Compression
	offset += 1

	// Extensions
	var extTypes []string
	if offset+2 <= len(data) {
		extLen := int((uint16(data[offset]) << 8) | uint16(data[offset+1]))
		offset += 2
		end := offset + extLen
		for offset+4 <= end {
			extType := (uint16(data[offset]) << 8) | uint16(data[offset+1])
			extDataLen := int((uint16(data[offset+2]) << 8) | uint16(data[offset+3]))
			if !isGrease(extType) {
				extTypes = append(extTypes, fmt.Sprintf("%04x", extType))
			}
			offset += 4 + extDataLen
		}
	}
	sort.Strings(extTypes)
	numExts := fmt.Sprintf("%02d", len(extTypes))
	hash := sha256.Sum256([]byte(strings.Join(extTypes, ",")))

	return fmt.Sprintf("t%s%s_%s", verStr, numExts, hex.EncodeToString(hash[:6]))
}

// CalculateCloudflareFingerprint computes a Cloudflare-style fingerprint
func CalculateCloudflareFingerprint(ch *ClientHello) string {
	// Cloudflare fingerprints involve complex ordering but often boil down to
	// a hash of specific ClientHello fields in a specific order
	var parts []string
	parts = append(parts, fmt.Sprintf("v:%d", ch.Version))

	var ciphers []string
	for _, c := range ch.CipherSuites {
		if !isGrease(c) {
			ciphers = append(ciphers, fmt.Sprintf("%x", c))
		}
	}
	parts = append(parts, "c:"+strings.Join(ciphers, ","))

	var exts []string
	for _, ext := range ch.Extensions {
		if !isGrease(ext.Type) {
			exts = append(exts, fmt.Sprintf("%x", ext.Type))
		}
	}
	parts = append(parts, "e:"+strings.Join(exts, ","))

	raw := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:16])
}

// CalculateDTLSJA3 computes the JA3 hash from a DTLS ClientHello payload
func CalculateDTLSJA3(payload []byte) (string, string) {
	if len(payload) < 60 { // Minimum DTLS ClientHello length (approx)
		return "", ""
	}

	// DTLS Record Header (13 bytes) + Handshake Header (12 bytes)
	offset := 25
	if len(payload) < offset+2 {
		return "", ""
	}

	version := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 34 // version (2) + random (32)

	// Session ID
	if len(payload) < offset+1 {
		return "", ""
	}
	sessLen := int(payload[offset])
	offset += 1 + sessLen

	// Cookie (DTLS specific)
	if len(payload) < offset+1 {
		return "", ""
	}
	cookieLen := int(payload[offset])
	offset += 1 + cookieLen

	// Cipher Suites
	if len(payload) < offset+2 {
		return "", ""
	}
	cipherLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	var ciphers []string
	for i := 0; i < cipherLen; i += 2 {
		ciphers = append(ciphers, fmt.Sprintf("%d", binary.BigEndian.Uint16(payload[offset+i:offset+i+2])))
	}
	offset += cipherLen

	// Compression
	if len(payload) < offset+1 {
		return "", ""
	}
	compLen := int(payload[offset])
	offset += 1 + compLen

	// Extensions
	var exts []string
	var curves []string
	var formats []string

	if len(payload) >= offset+2 {
		extFullLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
		offset += 2
		end := offset + extFullLen
		if end > len(payload) {
			end = len(payload)
		}

		for offset+4 <= end {
			extType := binary.BigEndian.Uint16(payload[offset : offset+2])
			extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
			exts = append(exts, fmt.Sprintf("%d", extType))
			offset += 4

			data := payload[offset : offset+extLen]
			if extType == 10 { // supported_groups (curves)
				if len(data) >= 2 {
					listLen := int(binary.BigEndian.Uint16(data[0:2]))
					for i := 0; i < listLen; i += 2 {
						curves = append(curves, fmt.Sprintf("%d", binary.BigEndian.Uint16(data[2+i:2+i+2])))
					}
				}
			} else if extType == 11 { // ec_point_formats
				if len(data) >= 1 {
					listLen := int(data[0])
					for i := 0; i < listLen; i++ {
						formats = append(formats, fmt.Sprintf("%d", data[1+i]))
					}
				}
			}
			offset += extLen
		}
	}

	ja3String := fmt.Sprintf("%d,%s,%s,%s,%s",
		version,
		strings.Join(ciphers, "-"),
		strings.Join(exts, "-"),
		strings.Join(curves, "-"),
		strings.Join(formats, "-"),
	)

	hash := md5.Sum([]byte(ja3String))
	return ja3String, hex.EncodeToString(hash[:])
}

// ParseDTLSClientHello parses a DTLS ClientHello from raw bytes
func ParseDTLSClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 60 {
		return nil, fmt.Errorf("data too short for DTLS ClientHello")
	}

	// DTLS Record (22=Handshake, 254=DTLS 1.0, 253=DTLS 1.2 at byte index 1)
	if data[0] != 22 {
		return nil, fmt.Errorf("not a DTLS handshake")
	}

	// Handshake type at offset 13 (Type 1 = ClientHello)
	if data[13] != 1 {
		return nil, fmt.Errorf("not a DTLS ClientHello")
	}

	offset := 25 // Record(13) + Handshake(12)
	ch := &ClientHello{
		Version: binary.BigEndian.Uint16(data[offset : offset+2]),
	}
	offset += 34 // Version(2) + Random(32)

	// Session ID
	sessLen := int(data[offset])
	offset++
	ch.SessionID = make([]byte, sessLen)
	copy(ch.SessionID, data[offset:offset+sessLen])
	offset += sessLen

	// Cookie (DTLS only)
	cookieLen := int(data[offset])
	offset += 1 + cookieLen

	// Cipher Suites
	cipherLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	for i := 0; i < cipherLen; i += 2 {
		ch.CipherSuites = append(ch.CipherSuites, binary.BigEndian.Uint16(data[offset+i:offset+i+2]))
	}
	offset += cipherLen

	// Compression
	compLen := int(data[offset])
	offset++
	for i := 0; i < compLen; i++ {
		ch.Compression = append(ch.Compression, data[offset+i])
	}
	offset += compLen

	// Extensions
	if offset+2 <= len(data) {
		extFullLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		end := offset + extFullLen
		for offset+4 <= end {
			extType := binary.BigEndian.Uint16(data[offset : offset+2])
			extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
			offset += 4

			if offset+extLen > len(data) {
				break
			}
			extData := make([]byte, extLen)
			copy(extData, data[offset:offset+extLen])
			ch.Extensions = append(ch.Extensions, Extension{Type: extType, Data: extData})
			offset += extLen
		}
	}

	return ch, nil
}

func isGrease(v uint16) bool {
	return isGREASE(v)
}
