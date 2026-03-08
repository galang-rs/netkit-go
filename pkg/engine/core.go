package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bacot120211/netkit-go/pkg/logger"
	"github.com/bacot120211/netkit-go/pkg/session"
)

// packetIDCounter provides globally unique, lock-free packet IDs.
var packetIDCounter atomic.Uint64

// NextPacketID returns a globally unique packet ID (atomic, no collisions).
func NextPacketID() uint64 {
	return packetIDCounter.Add(1)
}

// ReleasePacket aggressively clears all references so GC can collect immediately.
// Does NOT cache back into a pool — the object becomes garbage.
func ReleasePacket(p *Packet) {
	if p == nil {
		return
	}
	p.Payload = nil
	p.Metadata = nil
	p.Conn = nil
	p.Source = ""
	p.Dest = ""
	p.Protocol = ""
	p.ProcessName = ""
}

type coreEngine struct {
	sessionMgr   session.Manager
	interceptors []Interceptor
	mu           sync.RWMutex
	packetChan   chan *Packet
	pcapWriter   PacketWriter
	logger       *JSONLogger
	filter       *Filter
	mirrors      []Mirror
	closeChan    chan struct{}
	onDomain     func(domain string) // lowercase: protected by mu
	workerCount  int
	ca           interface {
		GetCertPEM() []byte
	}
}

func New() Engine {
	return &coreEngine{
		sessionMgr:   session.NewManager(),
		interceptors: make([]Interceptor, 0, 8),
		packetChan:   make(chan *Packet, 131072),
		closeChan:    make(chan struct{}),
		logger:       NewJSONLogger(os.Stdout),
	}
}

func (e *coreEngine) Start(ctx context.Context) error {
	// Adaptive worker count based on CPU cores (minimum 4)
	numWorkers := e.workerCount
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	if numWorkers < 4 {
		numWorkers = 4
	}
	e.logger.Info("Engine", fmt.Sprintf("Starting with %d workers...", numWorkers), nil)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case p, ok := <-e.packetChan:
					if !ok {
						return
					}
					if p != nil {
						e.processPacket(p)
					}
				}
			}
		}(i)
	}

	// Periodic memory cleanup — force GC to return memory to OS
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				debug.FreeOSMemory()
			}
		}
	}()

	<-ctx.Done()
	// Signal Ingest to stop
	close(e.closeChan)
	// We DO NOT close e.packetChan here because sniffer workers might still be calling Ingest.
	// Sending to a closed channel causes a panic. Workers will exit via ctx.Done().
	wg.Wait()
	return nil
}

func (e *coreEngine) Stop() error {
	logger.Println("[Engine] Stop requested...")
	e.mu.Lock()
	defer e.mu.Unlock()

	// The context cancellation in runner already starts the worker shutdown.
	// Here we just ensure interceptors are cleaned up with proper error propagation.
	var errs []error
	for _, i := range e.interceptors {
		if closer, ok := i.(interface{ Close() error }); ok {
			logger.Printf("[Engine] Closing interceptor: %s\n", i.Name())
			if err := closer.Close(); err != nil {
				errs = append(errs, fmt.Errorf("closing interceptor %s: %w", i.Name(), err))
			}
		}
	}

	// Aggressive cleanup: release interceptor slice
	e.interceptors = nil
	e.mirrors = nil
	e.pcapWriter = nil
	e.filter = nil

	// Force GC to reclaim all released memory
	debug.FreeOSMemory()

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (e *coreEngine) RegisterInterceptor(i Interceptor) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.interceptors = append(e.interceptors, i)
}

func (e *coreEngine) SessionManager() session.Manager {
	return e.sessionMgr
}

func (e *coreEngine) OnConnect(info *ConnInfo) *TunnelConfig {
	e.mu.RLock()
	interceptors := e.interceptors
	e.mu.RUnlock()
	for _, i := range interceptors {
		if cfg := i.OnConnect(info); cfg != nil {
			return cfg
		}
	}
	return nil
}

func (e *coreEngine) SetPcapWriter(w PacketWriter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pcapWriter = w
}

func (e *coreEngine) SetFilter(f *Filter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.filter = f
}

func (e *coreEngine) AddMirror(m Mirror) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mirrors = append(e.mirrors, m)
}

func (e *coreEngine) Ingest(p *Packet) {
	if p == nil {
		return
	}
	select {
	case <-e.closeChan:
		// Engine is closing — aggressively clean this packet
		ReleasePacket(p)
		return
	case e.packetChan <- p:
	default:
		// Channel full, drop packet and release memory immediately
		if e.logger != nil {
			e.logger.Error("Engine", "Packet channel full, dropping packet", map[string]interface{}{"id": p.ID})
		}
		ReleasePacket(p)
	}
}

func (e *coreEngine) processPacket(p *Packet) {
	_ = e.Process(p, nil)
	// After processing, aggressively clean up packet memory
	ReleasePacket(p)
}

func (e *coreEngine) Process(p *Packet, responder func([]byte) error) (action Action) {
	// 0. Panic Recovery
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("[Engine] CRITICAL PANIC RECOVERED: %v\n", r)
			logger.Printf("[Engine] Stack Trace:\n%s\n", debug.Stack())
			action = ActionContinue
		}
	}()

	// 0. Preliminary Filter
	e.mu.RLock()
	currentFilter := e.filter
	e.mu.RUnlock()

	if currentFilter != nil && !currentFilter.Matches(p) {
		return ActionContinue
	}

	// 1. Identify/Update Session (Bidirectional with ports)
	srcEnd := fmt.Sprintf("%s:%d", p.Source, p.SourcePort)
	dstEnd := fmt.Sprintf("%s:%d", p.Dest, p.DestPort)
	if srcEnd > dstEnd {
		srcEnd, dstEnd = dstEnd, srcEnd
	}
	sessionID := fmt.Sprintf("%s-%s-%s", p.Protocol, srcEnd, dstEnd)

	s, ok := e.sessionMgr.Get(sessionID)
	if !ok {
		s = e.sessionMgr.Create(sessionID, p.Protocol, p.Source, p.Dest)
	}

	s.LastSeen = time.Now()

	// 2. Run Interceptors — snapshot slice to avoid holding lock during callbacks
	pCtx := &PacketContext{
		Packet:    p,
		Session:   s,
		Action:    ActionContinue,
		Responder: responder,
		Conn:      p.Conn,
	}

	e.mu.RLock()
	interceptors := e.interceptors // copy slice header (safe, underlying array is append-only)
	e.mu.RUnlock()

	for _, i := range interceptors {
		if err := i.OnPacket(pCtx); err != nil {
			logger.Printf("[Engine] Interceptor %s error: %v\n", i.Name(), err)
			break
		}
		if pCtx.Action == ActionDrop {
			return ActionDrop
		}
	}

	// 3. Final action (log or forward) — single RLock, NO double lock
	if pCtx.Action != ActionDrop {
		e.mu.RLock()
		if e.pcapWriter != nil {
			if err := e.pcapWriter.WritePacket(p.Payload); err != nil {
				logger.Printf("[Engine] pcapWriter error: %v\n", err)
			}
		}
		for _, m := range e.mirrors {
			m.Clone(p.Payload)
		}
		e.mu.RUnlock()
	}

	return pCtx.Action
}

func (e *coreEngine) RegisterDomain(domain string) {
	e.mu.RLock()
	fn := e.onDomain
	e.mu.RUnlock()
	if fn != nil {
		fn(domain)
	}
}

func (e *coreEngine) SetOnDomain(fn func(string)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onDomain = fn
}

func (e *coreEngine) SetWorkerCount(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.workerCount = n
}

func (e *coreEngine) GetCA() interface {
	GetCertPEM() []byte
} {
	return e.ca
}

func (e *coreEngine) SetCA(ca interface {
	GetCertPEM() []byte
}) {
	e.ca = ca
}
