package engine

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Hexdump generates a formatted hex dump of a byte slice
func Hexdump(data []byte) string {
	var sb strings.Builder
	dump := hex.Dump(data)
	lines := strings.Split(dump, "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	return sb.String()
}

// LogHexdump prints a formatted hex dump to the console
func LogHexdump(component, msg string, data []byte) {
	fmt.Printf("[%s] %s:\n%s", component, msg, Hexdump(data))
}
