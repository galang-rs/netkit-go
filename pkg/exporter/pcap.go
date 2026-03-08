package exporter

import (
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PCAPWriter implements an advanced PCAP file writer with rotation, compression, and filtering.
type PCAPWriter struct {
	file        *os.File
	gzipWriter  *gzip.Writer
	mu          sync.Mutex
	path        string
	maxSize     int64
	maxAge      time.Duration
	currentSize int64
	startTime   time.Time
	compressed  bool
	filter      func(data []byte) bool
}

func NewPCAPWriter(path string) (*PCAPWriter, error) {
	w := &PCAPWriter{
		path: path,
	}

	if err := w.openFile(); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *PCAPWriter) openFile() error {
	f, err := os.Create(w.path)
	if err != nil {
		return err
	}
	w.file = f
	w.currentSize = 0
	w.startTime = time.Now()

	if w.compressed {
		w.gzipWriter = gzip.NewWriter(f)
	} else {
		w.gzipWriter = nil
	}

	return w.writeGlobalHeader()
}

func (w *PCAPWriter) writeGlobalHeader() error {
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4) // Magic Number
	binary.LittleEndian.PutUint16(header[4:6], 2)          // Major Version
	binary.LittleEndian.PutUint16(header[6:8], 4)          // Minor Version
	binary.LittleEndian.PutUint32(header[8:12], 0)         // GMT to local correction
	binary.LittleEndian.PutUint32(header[12:16], 0)        // accuracy of timestamps
	binary.LittleEndian.PutUint32(header[16:20], 65535)    // max length of captured packets
	binary.LittleEndian.PutUint32(header[20:24], 1)        // data link type (Ethernet=1)

	var target io.Writer = w.file
	if w.gzipWriter != nil {
		target = w.gzipWriter
	}

	n, err := target.Write(header)
	w.currentSize += int64(n)
	return err
}

// SetRotation sets the maximum size (bytes) and maximum age of a PCAP file before rotation.
func (w *PCAPWriter) SetRotation(maxSize int64, maxAge time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.maxSize = maxSize
	w.maxAge = maxAge
}

// SetCompression enables or disables gzip compression for future rotations.
func (w *PCAPWriter) SetCompression(enabled bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.compressed = enabled
}

// SetFilter sets a BPF-like filtering function for packets.
func (w *PCAPWriter) SetFilter(f func(data []byte) bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.filter = f
}

func (w *PCAPWriter) rotate() error {
	if w.gzipWriter != nil {
		_ = w.gzipWriter.Close()
	}
	if w.file != nil {
		_ = w.file.Close()
	}

	// Rename current file with timestamp
	timestamp := time.Now().Format("20060102-150405")
	dir := filepath.Dir(w.path)
	base := filepath.Base(w.path)
	ext := filepath.Ext(base)
	name := base[:len(base)-len(ext)]

	suffix := ""
	if w.compressed {
		suffix = ".gz"
	}
	newName := fmt.Sprintf("%s_%s%s%s", name, timestamp, ext, suffix)
	newPath := filepath.Join(dir, newName)

	_ = os.Rename(w.path, newPath)

	return w.openFile()
}

func (w *PCAPWriter) WritePacket(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.filter != nil && !w.filter(data) {
		return nil
	}

	// Check rotation
	if (w.maxSize > 0 && w.currentSize >= w.maxSize) || (w.maxAge > 0 && time.Since(w.startTime) >= w.maxAge) {
		if err := w.rotate(); err != nil {
			return err
		}
	}

	now := time.Now()
	sec := uint32(now.Unix())
	usec := uint32(now.UnixNano()/1000) % 1000000

	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], sec)
	binary.LittleEndian.PutUint32(header[4:8], usec)
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(data)))
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(data)))

	var target io.Writer = w.file
	if w.gzipWriter != nil {
		target = w.gzipWriter
	}

	n1, err := target.Write(header)
	if err != nil {
		return err
	}
	w.currentSize += int64(n1)

	n2, err := target.Write(data)
	if err != nil {
		return err
	}
	w.currentSize += int64(n2)

	return nil
}

func (w *PCAPWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.gzipWriter != nil {
		_ = w.gzipWriter.Close()
	}
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}
