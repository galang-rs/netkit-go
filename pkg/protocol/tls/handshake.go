package tls

import (
	"encoding/binary"
	"fmt"
)

// ClientHello represents a parsed TLS ClientHello for mutation
type ClientHello struct {
	Version      uint16
	Random       []byte
	SessionID    []byte
	CipherSuites []uint16
	Compression  []uint8
	Extensions   []Extension
	SNI          string
	ALPN         []string
}

type Extension struct {
	Type uint16
	Data []byte
}

// Reconstruct serializes the ClientHello back to a raw handshake message
func (ch *ClientHello) Reconstruct() []byte {
	// Calculate lengths
	cipherLen := len(ch.CipherSuites) * 2
	compLen := len(ch.Compression)
	extLen := 0
	for _, e := range ch.Extensions {
		extLen += 4 + len(e.Data)
	}

	bodyLen := 2 + 32 + 1 + len(ch.SessionID) + 2 + cipherLen + 1 + compLen + 2 + extLen
	res := make([]byte, 4+bodyLen)

	// Handshake Header
	res[0] = 1 // ClientHello
	res[1] = byte(bodyLen >> 16)
	res[2] = byte(bodyLen >> 8)
	res[3] = byte(bodyLen)

	offset := 4
	binary.BigEndian.PutUint16(res[offset:], ch.Version)
	offset += 2
	copy(res[offset:], ch.Random)
	offset += 32
	res[offset] = byte(len(ch.SessionID))
	offset += 1
	copy(res[offset:], ch.SessionID)
	offset += len(ch.SessionID)

	binary.BigEndian.PutUint16(res[offset:], uint16(cipherLen))
	offset += 2
	for _, c := range ch.CipherSuites {
		binary.BigEndian.PutUint16(res[offset:], c)
		offset += 2
	}

	res[offset] = byte(compLen)
	offset += 1
	for _, c := range ch.Compression {
		res[offset] = c
		offset += 1
	}

	binary.BigEndian.PutUint16(res[offset:], uint16(extLen))
	offset += 2
	for _, e := range ch.Extensions {
		binary.BigEndian.PutUint16(res[offset:], e.Type)
		binary.BigEndian.PutUint16(res[offset+2:], uint16(len(e.Data)))
		copy(res[offset+4:], e.Data)
		offset += 4 + len(e.Data)
	}

	return res
}

func ParseClientHello(data []byte) (*ClientHello, error) {
	// 1. Minimum TLS Handshake record: 5 (Record) + 4 (Handshake) + 34 (Version+Random) + 1 (SessID) = 44 bytes
	if len(data) < 44 {
		return nil, fmt.Errorf("data too short for TLS ClientHello")
	}

	// 2. Simple check for Record Layer (Handshake=22) and Handshake Type (ClientHello=1)
	if data[0] != 22 || data[5] != 1 {
		return nil, fmt.Errorf("not a ClientHello handshake")
	}

	offset := 9
	if offset+2 > len(data) {
		return nil, fmt.Errorf("no version field")
	}
	ch := &ClientHello{
		Version: binary.BigEndian.Uint16(data[offset : offset+2]),
	}
	offset += 2

	if offset+32 > len(data) {
		return nil, fmt.Errorf("no random field")
	}
	ch.Random = make([]byte, 32)
	copy(ch.Random, data[offset:offset+32])
	offset += 32

	if offset+1 > len(data) {
		return nil, fmt.Errorf("no session id length")
	}
	sessLen := int(data[offset])
	offset++

	if offset+sessLen > len(data) {
		return ch, nil
	}
	ch.SessionID = make([]byte, sessLen)
	copy(ch.SessionID, data[offset:offset+sessLen])
	offset += sessLen

	if offset+2 > len(data) {
		return nil, fmt.Errorf("no cipher suite length")
	}
	cipherLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+cipherLen > len(data) {
		return ch, nil // Return partial if truncated
	}
	for i := 0; i < cipherLen; i += 2 {
		ch.CipherSuites = append(ch.CipherSuites, binary.BigEndian.Uint16(data[offset+i:offset+i+2]))
	}
	offset += cipherLen

	if offset+1 > len(data) {
		return nil, fmt.Errorf("no compression length")
	}
	compLen := int(data[offset])
	offset++

	if offset+compLen > len(data) {
		return ch, nil
	}
	for i := 0; i < compLen; i++ {
		ch.Compression = append(ch.Compression, data[offset+i])
	}
	offset += compLen

	// Parse Extensions
	if offset+2 <= len(data) {
		extFullLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		end := offset + extFullLen
		if end > len(data) {
			end = len(data)
		}

		for offset+4 <= end {
			extType := binary.BigEndian.Uint16(data[offset : offset+2])
			extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
			offset += 4

			if offset+extLen > end {
				break
			}

			extData := make([]byte, extLen)
			copy(extData, data[offset:offset+extLen])
			ch.Extensions = append(ch.Extensions, Extension{Type: extType, Data: extData})

			// Extract SNI (Extension Type 0)
			if extType == 0 && extLen > 5 {
				// Server Name List Length (2) + Type (1) + Name Length (2) + Name
				nameListLen := binary.BigEndian.Uint16(extData[0:2])
				if int(nameListLen+2) <= extLen {
					nameType := extData[2]
					if nameType == 0 { // host_name
						nameLen := binary.BigEndian.Uint16(extData[3:5])
						if int(nameLen+5) <= extLen {
							ch.SNI = string(extData[5 : 5+nameLen])
						}
					}
				}
			}
			// Extract ALPN (Extension Type 16)
			if extType == 16 && extLen > 2 {
				// Protocol Name List Length (2) + List of (Length (1) + Name)
				listLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if listLen+2 <= extLen {
					pOffset := 2
					for pOffset+1 <= listLen+2 {
						pLen := int(extData[pOffset])
						pOffset++
						if pOffset+pLen <= listLen+2 {
							ch.ALPN = append(ch.ALPN, string(extData[pOffset:pOffset+pLen]))
							pOffset += pLen
						} else {
							break
						}
					}
				}
			}
			offset += extLen
		}
	}

	return ch, nil
}
