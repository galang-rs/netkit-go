package dom

import (
	"sync"
)

// EventHandler stores a registered event callback.
type EventHandler struct {
	Type    string
	Handler interface{} // goja.Callable stored as interface{}
}

// EventTarget manages event listeners for a node.
type EventTarget struct {
	mu       sync.Mutex
	handlers map[string][]interface{}
}

// NewEventTarget creates a new event target.
func NewEventTarget() *EventTarget {
	return &EventTarget{
		handlers: make(map[string][]interface{}),
	}
}

// AddEventListener registers an event handler.
func (et *EventTarget) AddEventListener(eventType string, handler interface{}) {
	et.mu.Lock()
	defer et.mu.Unlock()
	et.handlers[eventType] = append(et.handlers[eventType], handler)
}

// RemoveEventListener removes an event handler.
func (et *EventTarget) RemoveEventListener(eventType string, handler interface{}) {
	et.mu.Lock()
	defer et.mu.Unlock()
	handlers := et.handlers[eventType]
	for i, h := range handlers {
		if h == handler {
			et.handlers[eventType] = append(handlers[:i], handlers[i+1:]...)
			return
		}
	}
}

// GetHandlers returns all handlers for an event type.
func (et *EventTarget) GetHandlers(eventType string) []interface{} {
	et.mu.Lock()
	defer et.mu.Unlock()
	result := make([]interface{}, len(et.handlers[eventType]))
	copy(result, et.handlers[eventType])
	return result
}

// DOMEvent represents a W3C Event object.
type DOMEvent struct {
	Type             string
	Target           *Node
	CurrentTarget    *Node
	Bubbles          bool
	Cancelable       bool
	DefaultPrevented bool
	Detail           interface{}
}

// PreventDefault marks the event as default-prevented.
func (e *DOMEvent) PreventDefault() {
	if e.Cancelable {
		e.DefaultPrevented = true
	}
}

// ToMap exports the event as a JS-compatible map.
func (e *DOMEvent) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"type":             e.Type,
		"bubbles":          e.Bubbles,
		"cancelable":       e.Cancelable,
		"defaultPrevented": e.DefaultPrevented,
		"detail":           e.Detail,
		"preventDefault": func() {
			e.PreventDefault()
		},
		"stopPropagation":  func() {},
		"stopImmediatePropagation": func() {},
	}
}
