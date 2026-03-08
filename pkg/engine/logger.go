package engine

import (
	"io"

	"github.com/bacot120211/netkit-go/pkg/logger"
)

// LogEntry represents a structured log record (kept for compatibility if needed internally)
type LogEntry struct {
	Level     string
	Message   string
	Component string
}

// JSONLogger now name is a bit of a misnomer, but we keep it to avoid touching core.go too much.
// It handles colored console logging.
type JSONLogger struct {
	output  io.Writer
	logChan chan LogEntry
}

func NewJSONLogger(w io.Writer) *JSONLogger {
	l := &JSONLogger{
		output:  w,
		logChan: make(chan LogEntry, 10000), // Large buffer to avoid blocking
	}
	go l.startWorker()
	return l
}

func (l *JSONLogger) startWorker() {
	for entry := range l.logChan {
		msg := entry.Message
		if entry.Component != "" {
			msg = "[" + entry.Component + "] " + entry.Message
		}

		switch entry.Level {
		case "INFO", "SUCCESS":
			logger.Infof("%s\n", msg)
		case "WARN", "WARNING":
			logger.Warnf("%s\n", msg)
		case "ERROR":
			logger.Errorf("%s\n", msg)
		default:
			logger.Printf("%s\n", msg)
		}
	}
}

func (l *JSONLogger) Log(level, component, msg string, data map[string]interface{}) {
	entry := LogEntry{
		Level:     level,
		Component: component,
		Message:   msg,
	}

	select {
	case l.logChan <- entry:
	default:
		// Drop log if channel is full to prevent engine hang
	}
}

func (l *JSONLogger) Info(component, msg string, data map[string]interface{}) {
	l.Log("INFO", component, msg, data)
}

func (l *JSONLogger) Error(component, msg string, data map[string]interface{}) {
	l.Log("ERROR", component, msg, data)
}
