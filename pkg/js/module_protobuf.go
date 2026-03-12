package js

import (
	"encoding/binary"
	"fmt"
	"math"
)

// RegisterProtobufModule injects the Proto object into the JS context.
// Provides schema-less protobuf encode/decode using wire format directly.
//
// JS API:
//
//	var data = Proto.Encode([
//	    { field: 1, type: "string",  value: "Hello" },
//	    { field: 2, type: "varint",  value: 12345 },
//	    { field: 3, type: "bytes",   value: someBytes },
//	    { field: 4, type: "int32",   value: -1 },
//	    { field: 5, type: "sint32",  value: -1 },      // ZigZag encoded
//	    { field: 6, type: "fixed32", value: 42 },
//	    { field: 7, type: "fixed64", value: 42 },
//	    { field: 8, type: "double",  value: 3.14 },
//	    { field: 9, type: "float",   value: 1.5 },
//	    { field: 10, type: "message", value: [ ... ] }, // nested message
//	]);
//
//	var fields = Proto.Decode(data);
//	// → [{ field: 1, wire: 2, value: bytes }, ...]
//
//	var val = Proto.GetField(fields, 1);
//	var vals = Proto.GetRepeated(fields, 3);
//	var str = Proto.GetString(fields, 1);
//	var num = Proto.GetVarint(fields, 2);
func RegisterProtobufModule(jsCtx map[string]interface{}) {
	jsCtx["Proto"] = map[string]interface{}{
		// Encode converts a field definitions array to binary protobuf.
		"Encode": func(fields []interface{}) ([]byte, error) {
			return protoEncode(fields)
		},
		// Decode parses binary protobuf into a field array.
		// Each field: { field: number, wire: wireType, value: bytes }
		"Decode": func(data []byte) ([]interface{}, error) {
			return protoDecode(data)
		},
		// GetField returns the raw bytes value of the first field with the given number.
		"GetField": func(fields []interface{}, fieldNum int64) interface{} {
			for _, f := range fields {
				if m, ok := f.(map[string]interface{}); ok {
					if fn, ok := m["field"].(int64); ok && fn == fieldNum {
						return m["value"]
					}
				}
			}
			return nil
		},
		// GetRepeated returns all values for a given field number.
		"GetRepeated": func(fields []interface{}, fieldNum int64) []interface{} {
			var result []interface{}
			for _, f := range fields {
				if m, ok := f.(map[string]interface{}); ok {
					if fn, ok := m["field"].(int64); ok && fn == fieldNum {
						result = append(result, m["value"])
					}
				}
			}
			return result
		},
		// GetString returns the first field with the given number as string.
		"GetString": func(fields []interface{}, fieldNum int64) string {
			for _, f := range fields {
				if m, ok := f.(map[string]interface{}); ok {
					if fn, ok := m["field"].(int64); ok && fn == fieldNum {
						if b, ok := m["value"].([]byte); ok {
							return string(b)
						}
						if s, ok := m["value"].(string); ok {
							return s
						}
					}
				}
			}
			return ""
		},
		// GetVarint returns the first varint field with the given number.
		"GetVarint": func(fields []interface{}, fieldNum int64) int64 {
			for _, f := range fields {
				if m, ok := f.(map[string]interface{}); ok {
					if fn, ok := m["field"].(int64); ok && fn == fieldNum {
						if v, ok := m["value"].(int64); ok {
							return v
						}
						if v, ok := m["value"].(uint64); ok {
							return int64(v)
						}
					}
				}
			}
			return 0
		},
		// GetBytes returns the first length-delimited field as raw bytes.
		"GetBytes": func(fields []interface{}, fieldNum int64) []byte {
			for _, f := range fields {
				if m, ok := f.(map[string]interface{}); ok {
					if fn, ok := m["field"].(int64); ok && fn == fieldNum {
						if b, ok := m["value"].([]byte); ok {
							return b
						}
					}
				}
			}
			return nil
		},
		// GetMessage decodes a length-delimited field as a nested message.
		"GetMessage": func(fields []interface{}, fieldNum int64) ([]interface{}, error) {
			for _, f := range fields {
				if m, ok := f.(map[string]interface{}); ok {
					if fn, ok := m["field"].(int64); ok && fn == fieldNum {
						if b, ok := m["value"].([]byte); ok {
							return protoDecode(b)
						}
					}
				}
			}
			return nil, nil
		},
		// PackVarint encodes a uint64 as a varint byte sequence.
		"PackVarint": func(v uint64) []byte {
			buf := make([]byte, binary.MaxVarintLen64)
			n := binary.PutUvarint(buf, v)
			return buf[:n]
		},
		// UnpackVarint decodes a varint from bytes. Returns { value, bytesRead }.
		"UnpackVarint": func(data []byte) (map[string]interface{}, error) {
			v, n := binary.Uvarint(data)
			if n <= 0 {
				return nil, fmt.Errorf("invalid varint")
			}
			return map[string]interface{}{
				"value":     int64(v),
				"bytesRead": int64(n),
			}, nil
		},
	}
}

// ── Protobuf Wire Format Constants ──
const (
	wireVarint  = 0
	wire64bit   = 1
	wireBytes   = 2
	wire32bit   = 5
)

// protoEncode encodes an array of field definitions into binary protobuf.
func protoEncode(fields []interface{}) ([]byte, error) {
	var buf []byte

	for _, f := range fields {
		m, ok := f.(map[string]interface{})
		if !ok {
			continue
		}

		// Get field number
		var fieldNum uint64
		switch fn := m["field"].(type) {
		case int64:
			fieldNum = uint64(fn)
		case float64:
			fieldNum = uint64(fn)
		default:
			continue
		}

		// Get field type
		fieldType, _ := m["type"].(string)
		if fieldType == "" {
			fieldType = "bytes"
		}

		value := m["value"]

		switch fieldType {
		case "varint", "int32", "int64", "uint32", "uint64", "bool":
			var v uint64
			switch val := value.(type) {
			case int64:
				v = uint64(val)
			case float64:
				v = uint64(val)
			case bool:
				if val {
					v = 1
				}
			}
			buf = appendTag(buf, fieldNum, wireVarint)
			buf = appendVarint(buf, v)

		case "sint32", "sint64":
			// ZigZag encoding
			var v int64
			switch val := value.(type) {
			case int64:
				v = val
			case float64:
				v = int64(val)
			}
			encoded := uint64((v << 1) ^ (v >> 63))
			buf = appendTag(buf, fieldNum, wireVarint)
			buf = appendVarint(buf, encoded)

		case "fixed32", "sfixed32", "float":
			buf = appendTag(buf, fieldNum, wire32bit)
			b := make([]byte, 4)
			switch val := value.(type) {
			case int64:
				binary.LittleEndian.PutUint32(b, uint32(val))
			case float64:
				if fieldType == "float" {
					binary.LittleEndian.PutUint32(b, math.Float32bits(float32(val)))
				} else {
					binary.LittleEndian.PutUint32(b, uint32(val))
				}
			}
			buf = append(buf, b...)

		case "fixed64", "sfixed64", "double":
			buf = appendTag(buf, fieldNum, wire64bit)
			b := make([]byte, 8)
			switch val := value.(type) {
			case int64:
				binary.LittleEndian.PutUint64(b, uint64(val))
			case float64:
				if fieldType == "double" {
					binary.LittleEndian.PutUint64(b, math.Float64bits(val))
				} else {
					binary.LittleEndian.PutUint64(b, uint64(val))
				}
			}
			buf = append(buf, b...)

		case "string":
			var data []byte
			switch val := value.(type) {
			case string:
				data = []byte(val)
			case []byte:
				data = val
			}
			buf = appendTag(buf, fieldNum, wireBytes)
			buf = appendVarint(buf, uint64(len(data)))
			buf = append(buf, data...)

		case "bytes":
			var data []byte
			switch val := value.(type) {
			case []byte:
				data = val
			case string:
				data = []byte(val)
			}
			buf = appendTag(buf, fieldNum, wireBytes)
			buf = appendVarint(buf, uint64(len(data)))
			buf = append(buf, data...)

		case "message":
			// Nested message — value is another field array
			nestedFields, ok := value.([]interface{})
			if !ok {
				return nil, fmt.Errorf("message field %d value must be an array", fieldNum)
			}
			nested, err := protoEncode(nestedFields)
			if err != nil {
				return nil, fmt.Errorf("nested message field %d: %v", fieldNum, err)
			}
			buf = appendTag(buf, fieldNum, wireBytes)
			buf = appendVarint(buf, uint64(len(nested)))
			buf = append(buf, nested...)

		default:
			return nil, fmt.Errorf("unknown type '%s' for field %d", fieldType, fieldNum)
		}
	}

	return buf, nil
}

// protoDecode decodes binary protobuf into an array of field objects.
func protoDecode(data []byte) ([]interface{}, error) {
	var fields []interface{}
	pos := 0

	for pos < len(data) {
		// Read tag (field number + wire type)
		tag, n := readVarint(data[pos:])
		if n <= 0 {
			return nil, fmt.Errorf("invalid tag at offset %d", pos)
		}
		pos += n

		fieldNum := int64(tag >> 3)
		wireType := int64(tag & 0x7)

		field := map[string]interface{}{
			"field": fieldNum,
			"wire":  wireType,
		}

		switch wireType {
		case wireVarint:
			v, n := readVarint(data[pos:])
			if n <= 0 {
				return nil, fmt.Errorf("invalid varint at offset %d", pos)
			}
			pos += n
			field["value"] = int64(v)

		case wire64bit:
			if pos+8 > len(data) {
				return nil, fmt.Errorf("truncated 64-bit field at offset %d", pos)
			}
			field["value"] = data[pos : pos+8]
			pos += 8

		case wireBytes:
			length, n := readVarint(data[pos:])
			if n <= 0 {
				return nil, fmt.Errorf("invalid length at offset %d", pos)
			}
			pos += n
			if pos+int(length) > len(data) {
				return nil, fmt.Errorf("truncated bytes field at offset %d (need %d, have %d)", pos, length, len(data)-pos)
			}
			// Make a copy so the slice doesn't share backing array
			val := make([]byte, length)
			copy(val, data[pos:pos+int(length)])
			field["value"] = val
			pos += int(length)

		case wire32bit:
			if pos+4 > len(data) {
				return nil, fmt.Errorf("truncated 32-bit field at offset %d", pos)
			}
			field["value"] = data[pos : pos+4]
			pos += 4

		default:
			return nil, fmt.Errorf("unknown wire type %d at offset %d", wireType, pos)
		}

		fields = append(fields, field)
	}

	return fields, nil
}

// ── Helper functions ──

func appendTag(buf []byte, fieldNum uint64, wireType uint64) []byte {
	return appendVarint(buf, (fieldNum<<3)|wireType)
}

func appendVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	buf = append(buf, byte(v))
	return buf
}

func readVarint(data []byte) (uint64, int) {
	var result uint64
	var shift uint
	for i, b := range data {
		if i >= 10 {
			return 0, -1 // Too many bytes
		}
		result |= uint64(b&0x7F) << shift
		if b < 0x80 {
			return result, i + 1
		}
		shift += 7
	}
	return 0, -1
}
