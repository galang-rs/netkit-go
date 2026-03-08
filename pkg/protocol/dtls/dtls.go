// Package dtls implements a DTLS record layer and handshake parser
// for intercepting and analyzing DTLS traffic.
package dtls

import (
	"encoding/binary"
	"fmt"
)

// DTLS content types
const (
	ContentTypeChangeCipherSpec = 20
	ContentTypeAlert            = 21
	ContentTypeHandshake        = 22
	ContentTypeApplicationData  = 23
)

// DTLS handshake types
const (
	HandshakeTypeClientHello = 1
	HandshakeTypeServerHello = 2
	HandshakeTypeCertificate = 11
	HandshakeTypeKeyExchange = 12
	HandshakeTypeCertRequest = 13
	HandshakeTypeServerDone  = 14
	HandshakeTypeCertVerify  = 15
	HandshakeTypeFinished    = 20
)

// DTLS versions
const (
	VersionDTLS10 = 0xFEFF // DTLS 1.0 (based on TLS 1.1)
	VersionDTLS12 = 0xFEFD // DTLS 1.2 (based on TLS 1.2)
)

// RecordHeader represents a DTLS record layer header.
// Wire format: [1 ContentType][2 Version][2 Epoch][6 SequenceNumber][2 Length]
type RecordHeader struct {
	ContentType    uint8
	Version        uint16
	Epoch          uint16
	SequenceNumber uint64 // 48-bit, stored in lower 48 bits
	Length         uint16
}

// ParseRecordHeader parses a DTLS record header from raw bytes.
func ParseRecordHeader(data []byte) (*RecordHeader, error) {
	if len(data) < 13 {
		return nil, fmt.Errorf("DTLS record too short: %d bytes (need 13)", len(data))
	}

	h := &RecordHeader{
		ContentType: data[0],
		Version:     binary.BigEndian.Uint16(data[1:3]),
		Epoch:       binary.BigEndian.Uint16(data[3:5]),
		Length:      binary.BigEndian.Uint16(data[11:13]),
	}

	// 48-bit sequence number from bytes 5-10
	h.SequenceNumber = uint64(data[5])<<40 |
		uint64(data[6])<<32 |
		uint64(data[7])<<24 |
		uint64(data[8])<<16 |
		uint64(data[9])<<8 |
		uint64(data[10])

	return h, nil
}

// Serialize writes the record header to bytes.
func (h *RecordHeader) Serialize() []byte {
	b := make([]byte, 13)
	b[0] = h.ContentType
	binary.BigEndian.PutUint16(b[1:3], h.Version)
	binary.BigEndian.PutUint16(b[3:5], h.Epoch)
	// 48-bit sequence number
	b[5] = byte(h.SequenceNumber >> 40)
	b[6] = byte(h.SequenceNumber >> 32)
	b[7] = byte(h.SequenceNumber >> 24)
	b[8] = byte(h.SequenceNumber >> 16)
	b[9] = byte(h.SequenceNumber >> 8)
	b[10] = byte(h.SequenceNumber)
	binary.BigEndian.PutUint16(b[11:13], h.Length)
	return b
}

// IsDTLS checks if the version field matches a known DTLS version.
func (h *RecordHeader) IsDTLS() bool {
	return h.Version == VersionDTLS10 || h.Version == VersionDTLS12
}

// ContentTypeName returns a human-readable name for the content type.
func (h *RecordHeader) ContentTypeName() string {
	switch h.ContentType {
	case ContentTypeChangeCipherSpec:
		return "ChangeCipherSpec"
	case ContentTypeAlert:
		return "Alert"
	case ContentTypeHandshake:
		return "Handshake"
	case ContentTypeApplicationData:
		return "ApplicationData"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", h.ContentType)
	}
}

// HandshakeHeader represents a DTLS handshake message header.
// Wire format: [1 Type][3 Length][2 MessageSeq][3 FragmentOffset][3 FragmentLength]
type HandshakeHeader struct {
	Type           uint8
	Length         uint32 // 24-bit
	MessageSeq     uint16
	FragmentOffset uint32 // 24-bit
	FragmentLength uint32 // 24-bit
}

// ParseHandshakeHeader parses a handshake header from raw bytes.
func ParseHandshakeHeader(data []byte) (*HandshakeHeader, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("handshake header too short: %d bytes (need 12)", len(data))
	}

	h := &HandshakeHeader{
		Type:           data[0],
		Length:         uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]),
		MessageSeq:     binary.BigEndian.Uint16(data[4:6]),
		FragmentOffset: uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8]),
		FragmentLength: uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11]),
	}

	return h, nil
}

// HandshakeTypeName returns a human-readable name.
func (h *HandshakeHeader) HandshakeTypeName() string {
	switch h.Type {
	case HandshakeTypeClientHello:
		return "ClientHello"
	case HandshakeTypeServerHello:
		return "ServerHello"
	case HandshakeTypeCertificate:
		return "Certificate"
	case HandshakeTypeKeyExchange:
		return "ServerKeyExchange"
	case HandshakeTypeCertRequest:
		return "CertificateRequest"
	case HandshakeTypeServerDone:
		return "ServerHelloDone"
	case HandshakeTypeCertVerify:
		return "CertificateVerify"
	case HandshakeTypeFinished:
		return "Finished"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", h.Type)
	}
}

// ClientHello represents a parsed DTLS ClientHello message.
type ClientHello struct {
	Version            uint16
	Random             [32]byte
	SessionIDLength    uint8
	SessionID          []byte
	CookieLength       uint8
	Cookie             []byte
	CipherSuitesLength uint16
	CipherSuites       []uint16
	CompressionMethods []uint8
	ExtensionsLength   uint16
	SNI                string // Extracted from SNI extension
}

// ParseClientHello parses a DTLS ClientHello from handshake body (after handshake header).
func ParseClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 38 {
		return nil, fmt.Errorf("ClientHello too short: %d bytes", len(data))
	}

	ch := &ClientHello{
		Version: binary.BigEndian.Uint16(data[0:2]),
	}
	copy(ch.Random[:], data[2:34])

	pos := 34

	// Session ID
	if pos >= len(data) {
		return ch, nil
	}
	ch.SessionIDLength = data[pos]
	pos++
	if pos+int(ch.SessionIDLength) > len(data) {
		return ch, nil
	}
	ch.SessionID = data[pos : pos+int(ch.SessionIDLength)]
	pos += int(ch.SessionIDLength)

	// Cookie (DTLS-specific)
	if pos >= len(data) {
		return ch, nil
	}
	ch.CookieLength = data[pos]
	pos++
	if pos+int(ch.CookieLength) > len(data) {
		return ch, nil
	}
	ch.Cookie = data[pos : pos+int(ch.CookieLength)]
	pos += int(ch.CookieLength)

	// Cipher suites
	if pos+2 > len(data) {
		return ch, nil
	}
	ch.CipherSuitesLength = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	numSuites := int(ch.CipherSuitesLength) / 2
	for i := 0; i < numSuites && pos+2 <= len(data); i++ {
		suite := binary.BigEndian.Uint16(data[pos : pos+2])
		ch.CipherSuites = append(ch.CipherSuites, suite)
		pos += 2
	}

	// Compression methods
	if pos >= len(data) {
		return ch, nil
	}
	compLen := int(data[pos])
	pos++
	for i := 0; i < compLen && pos < len(data); i++ {
		ch.CompressionMethods = append(ch.CompressionMethods, data[pos])
		pos++
	}

	// Extensions
	if pos+2 > len(data) {
		return ch, nil
	}
	ch.ExtensionsLength = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	extEnd := pos + int(ch.ExtensionsLength)
	if extEnd > len(data) {
		extEnd = len(data)
	}

	// Parse extensions looking for SNI (type 0x0000)
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if extType == 0 && pos+extLen <= extEnd { // SNI extension
			ch.SNI = parseSNI(data[pos : pos+extLen])
		}

		pos += extLen
	}

	return ch, nil
}

// parseSNI extracts the server name from an SNI extension payload.
func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// SNI format: [2 list_length][1 name_type][2 name_length][name]
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

// IsDTLSPacket checks if raw bytes look like a DTLS record.
func IsDTLSPacket(data []byte) bool {
	if len(data) < 13 {
		return false
	}
	contentType := data[0]
	version := binary.BigEndian.Uint16(data[1:3])

	return (contentType >= 20 && contentType <= 25) &&
		(version == VersionDTLS10 || version == VersionDTLS12)
}
