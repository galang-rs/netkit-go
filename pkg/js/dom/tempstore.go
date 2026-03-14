package dom

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// TempStore manages temporary files per Document instance.
// All tracked files are deleted on Cleanup().
type TempStore struct {
	mu      sync.Mutex
	dir     string   // base directory for temp files
	files   []string // tracked file paths
	counter int      // auto-increment for default filenames
}

// NewTempStore creates a new temp store with the given base directory.
// If baseDir is empty, uses "logs/screenshot".
func NewTempStore(baseDir string) *TempStore {
	if baseDir == "" {
		baseDir = filepath.Join("logs", "screenshot")
	}
	return &TempStore{
		dir:   baseDir,
		files: make([]string, 0),
	}
}

// NextPath generates the next output path.
// If customPath is provided, uses that. Otherwise auto-increments: logs/screenshot/1.png, 2.png, ...
func (t *TempStore) NextPath(customPath string) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	if customPath != "" {
		dir := filepath.Dir(customPath)
		os.MkdirAll(dir, 0755)
		return customPath
	}

	t.counter++
	path := filepath.Join(t.dir, fmt.Sprintf("%d.png", t.counter))
	os.MkdirAll(t.dir, 0755)
	return path
}

// Track records a file path for later cleanup.
func (t *TempStore) Track(path string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.files = append(t.files, path)
}

// Cleanup removes all tracked temp files and the temp directory if empty.
func (t *TempStore) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, f := range t.files {
		os.Remove(f)
	}
	t.files = t.files[:0]
	t.counter = 0

	// Try to remove base dir if empty
	if t.dir != "" {
		os.Remove(t.dir)
	}
}

// Files returns a copy of all tracked file paths.
func (t *TempStore) Files() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]string, len(t.files))
	copy(result, t.files)
	return result
}

// Count returns the current auto-increment counter.
func (t *TempStore) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.counter
}
