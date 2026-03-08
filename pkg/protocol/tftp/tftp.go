package tftp

import (
	"encoding/binary"
	"fmt"
)

// TFTP Opcodes
const (
	OpRead  = 1
	OpWrite = 2
	OpData  = 3
	OpAck   = 4
	OpError = 5
)

type TFTPPacket struct {
	OpCode uint16
	Value  string // Filename, error message, etc.
}

func Parse(data []byte) (*TFTPPacket, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("tftp packet too short")
	}
	op := binary.BigEndian.Uint16(data[0:2])
	p := &TFTPPacket{OpCode: op}

	switch op {
	case OpRead, OpWrite:
		// Find null terminator for filename
		for i := 2; i < len(data); i++ {
			if data[i] == 0 {
				p.Value = string(data[2:i])
				break
			}
		}
	case OpError:
		p.Value = string(data[4 : len(data)-1])
	}

	return p, nil
}
