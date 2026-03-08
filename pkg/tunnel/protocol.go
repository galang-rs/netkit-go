package tunnel

import (
	"errors"
	"fmt"
)

// Commands
const (
	CmdAuth = "AUTH"
	CmdReq  = "REQ"
	CmdRes  = "RES"
	CmdErr  = "ERR"
	CmdOk   = "OK"
)

// Protocols
const (
	ProtoTCP   = "tcp"
	ProtoUDP   = "udp"
	ProtoHTTPS = "https"
	ProtoAll   = "all" // tcp + udp
)

// Error codes
const (
	ErrAuthFailed   = "AUTH_FAILED"
	ErrServerFull   = "SERVER_FULL"
	ErrPortFull     = "PORT_FULL"
	ErrInvalidCmd   = "INVALID_CMD"
	ErrUnknownProto = "UNKNOWN_PROTO"
)

type Command struct {
	Type string
	Args []string
}

func (c *Command) String() string {
	s := c.Type
	for _, arg := range c.Args {
		s += " " + arg
	}
	return s
}

func ParseCommand(line string) (*Command, error) {
	// Simple space-separated parsing
	var cmd Command
	n, err := fmt.Sscanf(line, "%s", &cmd.Type)
	if err != nil || n == 0 {
		return nil, errors.New("empty command")
	}
	// The rest are args... but Sscanf is not great for variable args.
	// We'll use strings.Fields instead in the implementation.
	return &cmd, nil
}
