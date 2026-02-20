// Package ack provides ACK (acknowledgement) tracking for MeshCore messages.
//
// The Tracker manages pending outbound messages that expect an ACK response.
// Each pending entry is identified by a 4-byte ACK hash (computed by
// crypto.ComputeAckHash). The tracker handles timeout detection and retry
// dispatch.
//
// This corresponds to the firmware's per-contact pending_ack / expected_ack
// logic spread across BaseChatMesh, ClientACL, and SensorMesh.
package ack

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const (
	// DefaultACKTimeout is the default time to wait for an ACK before
	// considering a send attempt failed.
	DefaultACKTimeout = 12 * time.Second

	// DefaultMaxRetries is the default number of retry attempts after the
	// initial send (total attempts = 1 + MaxRetries).
	DefaultMaxRetries = 3

	// checkInterval is the resolution of the tracker's timeout check loop.
	checkInterval = time.Second
)

// PendingACK represents an outbound message awaiting acknowledgement.
type PendingACK struct {
	// OnACK is called when the ACK is received. May be nil.
	OnACK func()

	// OnTimeout is called when all retry attempts are exhausted. May be nil.
	OnTimeout func()

	// Resend is called for each retry attempt. If it returns an error the
	// retry is counted but the error is logged. May be nil (no retries).
	Resend func() error

	sentAt  time.Time
	retries int
}

// TrackerConfig configures an ACK Tracker.
type TrackerConfig struct {
	// ACKTimeout is the maximum time to wait for an ACK per attempt.
	// Default: 12 seconds.
	ACKTimeout time.Duration

	// MaxRetries is the number of retry attempts after the initial send.
	// Default: 3 (total 4 attempts).
	MaxRetries int

	// Logger for tracker events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// Tracker tracks pending ACKs and handles timeouts and retries.
type Tracker struct {
	cfg    TrackerConfig
	log    *slog.Logger
	mu     sync.Mutex
	pending map[uint32]*PendingACK
	cancel  context.CancelFunc

	// nowFn allows overriding time.Now() for testing.
	nowFn func() time.Time
}

// NewTracker creates an ACK tracker with the given configuration.
func NewTracker(cfg TrackerConfig) *Tracker {
	if cfg.ACKTimeout <= 0 {
		cfg.ACKTimeout = DefaultACKTimeout
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = DefaultMaxRetries
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Tracker{
		cfg:     cfg,
		log:     logger.WithGroup("ack"),
		pending: make(map[uint32]*PendingACK),
		nowFn:   time.Now,
	}
}

// Track registers a pending ACK. If a pending entry with the same hash
// already exists it is replaced (the old entry's callbacks are not called).
func (t *Tracker) Track(hash uint32, pending PendingACK) {
	t.mu.Lock()
	defer t.mu.Unlock()

	pending.sentAt = t.nowFn()
	pending.retries = 0
	t.pending[hash] = &pending
}

// Resolve marks an ACK as received. Returns true if the hash was pending.
// If found, the entry's OnACK callback is called and the entry is removed.
func (t *Tracker) Resolve(hash uint32) bool {
	t.mu.Lock()
	p, ok := t.pending[hash]
	if ok {
		delete(t.pending, hash)
	}
	t.mu.Unlock()

	if ok && p.OnACK != nil {
		p.OnACK()
	}
	return ok
}

// Cancel removes a pending ACK without calling any callbacks.
func (t *Tracker) Cancel(hash uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pending, hash)
}

// PendingCount returns the number of pending ACKs.
func (t *Tracker) PendingCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pending)
}

// Start begins the timeout check loop. Blocks until the context is cancelled.
func (t *Tracker) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	t.mu.Lock()
	t.cancel = cancel
	t.mu.Unlock()

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.checkTimeouts()
		}
	}
}

// Stop cancels the tracker's context, stopping the timeout check loop.
func (t *Tracker) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
}

// checkTimeouts checks all pending ACKs for timeout and triggers retries
// or timeout callbacks as appropriate.
func (t *Tracker) checkTimeouts() {
	t.mu.Lock()
	now := t.nowFn()

	var timedOut []uint32
	var retries []uint32

	for hash, p := range t.pending {
		if now.Sub(p.sentAt) < t.cfg.ACKTimeout {
			continue
		}
		if p.retries < t.cfg.MaxRetries && p.Resend != nil {
			retries = append(retries, hash)
		} else {
			timedOut = append(timedOut, hash)
		}
	}

	// Collect entries to process outside the lock
	retryEntries := make(map[uint32]*PendingACK, len(retries))
	for _, hash := range retries {
		p := t.pending[hash]
		p.retries++
		p.sentAt = now
		retryEntries[hash] = p
	}

	timeoutEntries := make(map[uint32]*PendingACK, len(timedOut))
	for _, hash := range timedOut {
		timeoutEntries[hash] = t.pending[hash]
		delete(t.pending, hash)
	}
	t.mu.Unlock()

	// Execute retries outside the lock
	for hash, p := range retryEntries {
		if err := p.Resend(); err != nil {
			t.log.Warn("retry failed", "hash", hash, "attempt", p.retries, "error", err)
		} else {
			t.log.Debug("retrying", "hash", hash, "attempt", p.retries)
		}
	}

	// Execute timeout callbacks outside the lock
	for hash, p := range timeoutEntries {
		t.log.Debug("ack timed out", "hash", hash, "retries", p.retries)
		if p.OnTimeout != nil {
			p.OnTimeout()
		}
	}
}
