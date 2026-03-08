package dtls

import (
	"encoding/binary"
	"testing"
)

// --- Record Header Tests ---

func TestParseRecordHeader_Valid(t *testing.T) {
	data := make([]byte, 13)
	data[0] = ContentTypeHandshake
	binary.BigEndian.PutUint16(data[1:3], VersionDTLS12)
	binary.BigEndian.PutUint16(data[3:5], 0) // Epoch
	data[5] = 0
	data[6] = 0
	data[7] = 0
	data[8] = 0
	data[9] = 0
	data[10] = 1                                 // SeqNum = 1
	binary.BigEndian.PutUint16(data[11:13], 100) // Length

	h, err := ParseRecordHeader(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if h.ContentType != ContentTypeHandshake {
		t.Errorf("expected ContentTypeHandshake, got %d", h.ContentType)
	}
	if h.Version != VersionDTLS12 {
		t.Errorf("expected DTLS 1.2, got 0x%04x", h.Version)
	}
	if !h.IsDTLS() {
		t.Error("should be valid DTLS")
	}
	if h.SequenceNumber != 1 {
		t.Errorf("expected seq 1, got %d", h.SequenceNumber)
	}
	if h.Length != 100 {
		t.Errorf("expected length 100, got %d", h.Length)
	}
}

func TestParseRecordHeader_TooShort(t *testing.T) {
	_, err := ParseRecordHeader([]byte{0x16, 0xFE})
	if err == nil {
		t.Error("expected error for too-short data")
	}
}

func TestRecordHeader_Serialize(t *testing.T) {
	h := &RecordHeader{
		ContentType:    ContentTypeHandshake,
		Version:        VersionDTLS12,
		Epoch:          0,
		SequenceNumber: 42,
		Length:         200,
	}

	data := h.Serialize()
	parsed, err := ParseRecordHeader(data)
	if err != nil {
		t.Fatalf("re-parse error: %v", err)
	}
	if parsed.ContentType != h.ContentType {
		t.Error("ContentType mismatch")
	}
	if parsed.Version != h.Version {
		t.Error("Version mismatch")
	}
	if parsed.SequenceNumber != h.SequenceNumber {
		t.Errorf("SequenceNumber: got %d, want %d", parsed.SequenceNumber, h.SequenceNumber)
	}
	if parsed.Length != h.Length {
		t.Errorf("Length: got %d, want %d", parsed.Length, h.Length)
	}
}

func TestRecordHeader_IsDTLS(t *testing.T) {
	tests := []struct {
		version uint16
		isDTLS  bool
	}{
		{VersionDTLS10, true},
		{VersionDTLS12, true},
		{0x0301, false}, // TLS 1.0
		{0x0303, false}, // TLS 1.2
	}
	for _, tc := range tests {
		h := &RecordHeader{Version: tc.version}
		if h.IsDTLS() != tc.isDTLS {
			t.Errorf("Version 0x%04x: IsDTLS() = %v, want %v", tc.version, h.IsDTLS(), tc.isDTLS)
		}
	}
}

func TestRecordHeader_ContentTypeName(t *testing.T) {
	tests := []struct {
		ct   uint8
		name string
	}{
		{ContentTypeChangeCipherSpec, "ChangeCipherSpec"},
		{ContentTypeAlert, "Alert"},
		{ContentTypeHandshake, "Handshake"},
		{ContentTypeApplicationData, "ApplicationData"},
		{99, "Unknown(0x63)"},
	}
	for _, tc := range tests {
		h := &RecordHeader{ContentType: tc.ct}
		if h.ContentTypeName() != tc.name {
			t.Errorf("ContentType %d: got '%s', want '%s'", tc.ct, h.ContentTypeName(), tc.name)
		}
	}
}

// --- Handshake Header Tests ---

func TestParseHandshakeHeader_Valid(t *testing.T) {
	data := make([]byte, 12)
	data[0] = HandshakeTypeClientHello
	data[1] = 0
	data[2] = 0x01
	data[3] = 0x00                           // Length = 256
	binary.BigEndian.PutUint16(data[4:6], 0) // MessageSeq
	data[6] = 0
	data[7] = 0
	data[8] = 0 // FragmentOffset = 0
	data[9] = 0
	data[10] = 0x01
	data[11] = 0x00 // FragmentLength = 256

	h, err := ParseHandshakeHeader(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if h.Type != HandshakeTypeClientHello {
		t.Errorf("expected ClientHello, got %d", h.Type)
	}
	if h.Length != 256 {
		t.Errorf("expected length 256, got %d", h.Length)
	}
	if h.HandshakeTypeName() != "ClientHello" {
		t.Errorf("expected 'ClientHello', got '%s'", h.HandshakeTypeName())
	}
}

func TestParseHandshakeHeader_TooShort(t *testing.T) {
	_, err := ParseHandshakeHeader([]byte{0x01, 0x00})
	if err == nil {
		t.Error("expected error for too-short data")
	}
}

func TestHandshakeHeader_TypeNames(t *testing.T) {
	tests := []struct {
		typ  uint8
		name string
	}{
		{HandshakeTypeClientHello, "ClientHello"},
		{HandshakeTypeServerHello, "ServerHello"},
		{HandshakeTypeCertificate, "Certificate"},
		{HandshakeTypeFinished, "Finished"},
	}
	for _, tc := range tests {
		h := &HandshakeHeader{Type: tc.typ}
		if h.HandshakeTypeName() != tc.name {
			t.Errorf("Type %d: got '%s', want '%s'", tc.typ, h.HandshakeTypeName(), tc.name)
		}
	}
}

// --- ClientHello Tests ---

func TestParseClientHello_Basic(t *testing.T) {
	// Build a minimal DTLS ClientHello
	data := make([]byte, 0, 256)

	// Version: DTLS 1.2
	data = append(data, 0xFE, 0xFD)
	// Random: 32 bytes
	random := make([]byte, 32)
	random[0] = 0xAA
	data = append(data, random...)
	// Session ID length: 0
	data = append(data, 0x00)
	// Cookie length: 0
	data = append(data, 0x00)
	// Cipher suites length: 4 (2 suites)
	data = append(data, 0x00, 0x04)
	data = append(data, 0xC0, 0x2B) // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	data = append(data, 0xC0, 0x2F) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	// Compression methods: 1 (null)
	data = append(data, 0x01, 0x00)

	ch, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if ch.Version != VersionDTLS12 {
		t.Errorf("expected DTLS 1.2, got 0x%04x", ch.Version)
	}
	if ch.Random[0] != 0xAA {
		t.Error("random byte mismatch")
	}
	if len(ch.CipherSuites) != 2 {
		t.Errorf("expected 2 cipher suites, got %d", len(ch.CipherSuites))
	}
	if ch.CipherSuites[0] != 0xC02B {
		t.Errorf("expected cipher suite 0xC02B, got 0x%04x", ch.CipherSuites[0])
	}
}

func TestParseClientHello_WithSNI(t *testing.T) {
	data := make([]byte, 0, 256)

	// Version
	data = append(data, 0xFE, 0xFD)
	// Random
	data = append(data, make([]byte, 32)...)
	// Session ID length: 0
	data = append(data, 0x00)
	// Cookie length: 0
	data = append(data, 0x00)
	// Cipher suites: 2 bytes (1 suite)
	data = append(data, 0x00, 0x02, 0x00, 0xFF)
	// Compression: 1 (null)
	data = append(data, 0x01, 0x00)

	// Extensions
	sniHostname := "example.com"
	sniExt := buildSNIExtension(sniHostname)
	extLen := len(sniExt)
	data = append(data, byte(extLen>>8), byte(extLen))
	data = append(data, sniExt...)

	ch, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if ch.SNI != sniHostname {
		t.Errorf("expected SNI '%s', got '%s'", sniHostname, ch.SNI)
	}
}

func TestParseClientHello_WithCookie(t *testing.T) {
	data := make([]byte, 0, 256)
	data = append(data, 0xFE, 0xFD)
	data = append(data, make([]byte, 32)...)
	data = append(data, 0x00)                         // Session ID len: 0
	data = append(data, 0x04, 0xDE, 0xAD, 0xBE, 0xEF) // Cookie: 4 bytes
	data = append(data, 0x00, 0x02, 0x00, 0xFF)       // 1 cipher suite
	data = append(data, 0x01, 0x00)                   // Compression

	ch, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if ch.CookieLength != 4 {
		t.Errorf("expected cookie length 4, got %d", ch.CookieLength)
	}
	if ch.Cookie[0] != 0xDE || ch.Cookie[3] != 0xEF {
		t.Error("cookie data mismatch")
	}
}

func TestParseClientHello_TooShort(t *testing.T) {
	_, err := ParseClientHello([]byte{0xFE, 0xFD})
	if err == nil {
		t.Error("expected error for too-short data")
	}
}

// --- IsDTLSPacket Tests ---

func TestIsDTLSPacket_Valid(t *testing.T) {
	data := make([]byte, 13)
	data[0] = ContentTypeHandshake
	binary.BigEndian.PutUint16(data[1:3], VersionDTLS12)
	if !IsDTLSPacket(data) {
		t.Error("should detect valid DTLS packet")
	}
}

func TestIsDTLSPacket_TLS(t *testing.T) {
	data := make([]byte, 13)
	data[0] = ContentTypeHandshake
	binary.BigEndian.PutUint16(data[1:3], 0x0303) // TLS 1.2
	if IsDTLSPacket(data) {
		t.Error("TLS packet should not be detected as DTLS")
	}
}

func TestIsDTLSPacket_TooShort(t *testing.T) {
	if IsDTLSPacket([]byte{0x16}) {
		t.Error("should not detect too-short data as DTLS")
	}
}

// --- Helpers ---

func buildSNIExtension(hostname string) []byte {
	// SNI extension: type=0x0000, then SNI list
	nameBytes := []byte(hostname)
	nameLen := len(nameBytes)

	// SNI list entry: [1 type=0][2 name_len][name]
	sniEntry := make([]byte, 3+nameLen)
	sniEntry[0] = 0 // Host name type
	binary.BigEndian.PutUint16(sniEntry[1:3], uint16(nameLen))
	copy(sniEntry[3:], nameBytes)

	// SNI list: [2 list_len][entries]
	sniList := make([]byte, 2+len(sniEntry))
	binary.BigEndian.PutUint16(sniList[0:2], uint16(len(sniEntry)))
	copy(sniList[2:], sniEntry)

	// Extension: [2 type=0x0000][2 data_len][data]
	ext := make([]byte, 4+len(sniList))
	binary.BigEndian.PutUint16(ext[0:2], 0x0000) // SNI type
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(sniList)))
	copy(ext[4:], sniList)

	return ext
}
