package tls

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// JA3Context holds the fields required for JA3 fingerprinting
type JA3Context struct {
	Version      uint16
	Ciphers      []uint16
	Extensions   []uint16
	Curves       []uint16
	CurveFormats []uint8
}

// CalculateJA3 computes the JA3 hash from a ClientHello payload
func CalculateJA3(payload []byte) (string, string) {
	if len(payload) < 43 { // Minimum ClientHello length
		return "", ""
	}

	// Basic check for Handshake and ClientHello
	if payload[0] != 22 { // Handshake
		return "", ""
	}

	// Skip TLS header (5 bytes) + Handshake Type (1) + length (3)
	// total 9 bytes offset to Version in Handshake
	offset := 9
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

	// Cipher Suites
	if len(payload) < offset+2 {
		return "", ""
	}
	cipherLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	if len(payload) < offset+cipherLen {
		return "", ""
	}

	var ciphers []string
	for i := 0; i < cipherLen; i += 2 {
		c := binary.BigEndian.Uint16(payload[offset+i : offset+i+2])
		if !isGREASE(c) {
			ciphers = append(ciphers, fmt.Sprintf("%d", c))
		}
	}
	offset += cipherLen

	// Compression
	if len(payload) < offset+1 {
		return "", ""
	}
	compLen := int(payload[offset])
	if len(payload) < offset+1+compLen {
		return "", ""
	}
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

			// Safety check for extension data boundary
			if offset+4+extLen > len(payload) {
				// Malformed extension, truncate or skip
				break
			}

			// JA3 spec: skip GREASE extension types
			if !isGREASE(extType) {
				exts = append(exts, fmt.Sprintf("%d", extType))
			}
			offset += 4

			data := payload[offset : offset+extLen]
			if extType == 10 { // supported_groups (curves)
				if len(data) >= 2 {
					listLen := int(binary.BigEndian.Uint16(data[0:2]))
					if len(data) >= 2+listLen {
						for i := 0; i < listLen; i += 2 {
							if 2+i+2 <= len(data) {
								curve := binary.BigEndian.Uint16(data[2+i : 2+i+2])
								// JA3 spec: skip GREASE curves
								if !isGREASE(curve) {
									curves = append(curves, fmt.Sprintf("%d", curve))
								}
							}
						}
					}
				}
			} else if extType == 11 { // ec_point_formats
				if len(data) >= 1 {
					listLen := int(data[0])
					if len(data) >= 1+listLen {
						for i := 0; i < listLen; i++ {
							formats = append(formats, fmt.Sprintf("%d", data[1+i]))
						}
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

// isGREASE returns true if the value matches the GREASE pattern (RFC 8701).
// GREASE values have the form 0xXaXa where both nibbles are equal.
func isGREASE(v uint16) bool {
	if v&0x0f == 0x0a && v>>8 == v&0xff {
		return true
	}
	return false
}
