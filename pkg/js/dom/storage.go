package dom

import (
	"sync"
)

// Storage simulates browser localStorage/sessionStorage.
type Storage struct {
	mu   sync.RWMutex
	data map[string]string
	keys []string // maintain insertion order
}

// NewStorage creates an empty storage.
func NewStorage() *Storage {
	return &Storage{
		data: make(map[string]string),
		keys: make([]string, 0),
	}
}

// SetItem sets a key-value pair.
func (s *Storage) SetItem(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data[key]; !exists {
		s.keys = append(s.keys, key)
	}
	s.data[key] = value
}

// GetItem returns the value for a key, or empty string if not found.
func (s *Storage) GetItem(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.data[key]
	return val, ok
}

// RemoveItem removes a key.
func (s *Storage) RemoveItem(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	for i, k := range s.keys {
		if k == key {
			s.keys = append(s.keys[:i], s.keys[i+1:]...)
			break
		}
	}
}

// Clear removes all items.
func (s *Storage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = make(map[string]string)
	s.keys = s.keys[:0]
}

// Length returns the number of stored items.
func (s *Storage) Length() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}

// Key returns the key at the given index, or empty string.
func (s *Storage) Key(index int) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if index < 0 || index >= len(s.keys) {
		return ""
	}
	return s.keys[index]
}

// Keys returns all keys.
func (s *Storage) Keys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, len(s.keys))
	copy(result, s.keys)
	return result
}

// Snapshot returns a copy of all key-value pairs.
func (s *Storage) Snapshot() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]string, len(s.data))
	for k, v := range s.data {
		cp[k] = v
	}
	return cp
}

// AsMap returns a JS-compatible map with getItem/setItem/removeItem.
func (s *Storage) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"getItem": func(key string) interface{} {
			val, ok := s.GetItem(key)
			if !ok {
				return nil
			}
			return val
		},
		"setItem":    func(key, value string) { s.SetItem(key, value) },
		"removeItem": func(key string) { s.RemoveItem(key) },
		"clear":      func() { s.Clear() },
		"length":     s.Length(),
		"key": func(index int) interface{} {
			k := s.Key(index)
			if k == "" {
				return nil
			}
			return k
		},
	}
}
