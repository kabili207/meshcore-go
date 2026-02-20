package ack

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestTracker_NewTracker_Defaults(t *testing.T) {
	tr := NewTracker(TrackerConfig{})

	if tr.cfg.ACKTimeout != DefaultACKTimeout {
		t.Errorf("default ACKTimeout = %v, want %v", tr.cfg.ACKTimeout, DefaultACKTimeout)
	}
	if tr.cfg.MaxRetries != 0 {
		t.Errorf("default MaxRetries = %d, want 0 (zero-value is valid)", tr.cfg.MaxRetries)
	}
	if tr.PendingCount() != 0 {
		t.Errorf("new tracker should have 0 pending, got %d", tr.PendingCount())
	}
}

func TestTracker_Track_And_Resolve(t *testing.T) {
	tr := NewTracker(TrackerConfig{ACKTimeout: time.Minute})

	var acked atomic.Bool
	tr.Track(0xDEADBEEF, PendingACK{
		OnACK: func() { acked.Store(true) },
	})

	if tr.PendingCount() != 1 {
		t.Errorf("PendingCount = %d, want 1", tr.PendingCount())
	}

	ok := tr.Resolve(0xDEADBEEF)
	if !ok {
		t.Error("Resolve should return true for pending hash")
	}
	if !acked.Load() {
		t.Error("OnACK should have been called")
	}
	if tr.PendingCount() != 0 {
		t.Errorf("PendingCount = %d, want 0 after resolve", tr.PendingCount())
	}
}

func TestTracker_Resolve_Unknown(t *testing.T) {
	tr := NewTracker(TrackerConfig{ACKTimeout: time.Minute})

	ok := tr.Resolve(0x12345678)
	if ok {
		t.Error("Resolve should return false for unknown hash")
	}
}

func TestTracker_Resolve_NilCallback(t *testing.T) {
	tr := NewTracker(TrackerConfig{ACKTimeout: time.Minute})

	tr.Track(0xAAAA, PendingACK{}) // no OnACK
	ok := tr.Resolve(0xAAAA)
	if !ok {
		t.Error("Resolve should return true even with nil OnACK")
	}
}

func TestTracker_Cancel(t *testing.T) {
	tr := NewTracker(TrackerConfig{ACKTimeout: time.Minute})

	var called atomic.Bool
	tr.Track(0xBBBB, PendingACK{
		OnACK:     func() { called.Store(true) },
		OnTimeout: func() { called.Store(true) },
	})

	tr.Cancel(0xBBBB)

	if tr.PendingCount() != 0 {
		t.Errorf("PendingCount = %d, want 0 after cancel", tr.PendingCount())
	}

	// Neither callback should fire
	ok := tr.Resolve(0xBBBB)
	if ok {
		t.Error("Resolve after cancel should return false")
	}
	if called.Load() {
		t.Error("no callbacks should have been called")
	}
}

func TestTracker_Track_Replaces(t *testing.T) {
	tr := NewTracker(TrackerConfig{ACKTimeout: time.Minute})

	var first, second atomic.Bool
	tr.Track(0xCCCC, PendingACK{OnACK: func() { first.Store(true) }})
	tr.Track(0xCCCC, PendingACK{OnACK: func() { second.Store(true) }})

	if tr.PendingCount() != 1 {
		t.Errorf("PendingCount = %d, want 1", tr.PendingCount())
	}

	tr.Resolve(0xCCCC)
	if first.Load() {
		t.Error("first OnACK should NOT have been called (replaced)")
	}
	if !second.Load() {
		t.Error("second OnACK should have been called")
	}
}

func TestTracker_Timeout_NoRetries(t *testing.T) {
	tr := NewTracker(TrackerConfig{
		ACKTimeout: 100 * time.Millisecond,
		MaxRetries: 0,
	})

	now := time.Now()
	tr.nowFn = func() time.Time { return now }

	var timedOut atomic.Bool
	tr.Track(0x1111, PendingACK{
		OnTimeout: func() { timedOut.Store(true) },
	})

	// Advance past timeout
	now = now.Add(200 * time.Millisecond)
	tr.checkTimeouts()

	if !timedOut.Load() {
		t.Error("OnTimeout should have been called")
	}
	if tr.PendingCount() != 0 {
		t.Errorf("PendingCount = %d, want 0 after timeout", tr.PendingCount())
	}
}

func TestTracker_Timeout_WithRetries(t *testing.T) {
	tr := NewTracker(TrackerConfig{
		ACKTimeout: 100 * time.Millisecond,
		MaxRetries: 2,
	})

	now := time.Now()
	tr.nowFn = func() time.Time { return now }

	var retries atomic.Int32
	var timedOut atomic.Bool
	tr.Track(0x2222, PendingACK{
		Resend:    func() error { retries.Add(1); return nil },
		OnTimeout: func() { timedOut.Store(true) },
	})

	// First timeout → retry 1
	now = now.Add(200 * time.Millisecond)
	tr.checkTimeouts()

	if retries.Load() != 1 {
		t.Errorf("retries = %d, want 1", retries.Load())
	}
	if timedOut.Load() {
		t.Error("should not have timed out yet (retry 1)")
	}
	if tr.PendingCount() != 1 {
		t.Errorf("PendingCount = %d, want 1 during retries", tr.PendingCount())
	}

	// Second timeout → retry 2
	now = now.Add(200 * time.Millisecond)
	tr.checkTimeouts()

	if retries.Load() != 2 {
		t.Errorf("retries = %d, want 2", retries.Load())
	}
	if timedOut.Load() {
		t.Error("should not have timed out yet (retry 2)")
	}

	// Third timeout → max retries exhausted, call OnTimeout
	now = now.Add(200 * time.Millisecond)
	tr.checkTimeouts()

	if retries.Load() != 2 {
		t.Errorf("retries = %d, want 2 (no more retries)", retries.Load())
	}
	if !timedOut.Load() {
		t.Error("OnTimeout should have been called after max retries")
	}
	if tr.PendingCount() != 0 {
		t.Errorf("PendingCount = %d, want 0 after final timeout", tr.PendingCount())
	}
}

func TestTracker_Resolve_During_Retries(t *testing.T) {
	tr := NewTracker(TrackerConfig{
		ACKTimeout: 100 * time.Millisecond,
		MaxRetries: 3,
	})

	now := time.Now()
	tr.nowFn = func() time.Time { return now }

	var acked atomic.Bool
	var timedOut atomic.Bool
	tr.Track(0x3333, PendingACK{
		Resend:    func() error { return nil },
		OnACK:     func() { acked.Store(true) },
		OnTimeout: func() { timedOut.Store(true) },
	})

	// First timeout → retry
	now = now.Add(200 * time.Millisecond)
	tr.checkTimeouts()

	// ACK arrives during retry phase
	ok := tr.Resolve(0x3333)
	if !ok {
		t.Error("Resolve should succeed during retries")
	}
	if !acked.Load() {
		t.Error("OnACK should have been called")
	}
	if timedOut.Load() {
		t.Error("OnTimeout should NOT have been called")
	}
}

func TestTracker_Multiple_Pending(t *testing.T) {
	tr := NewTracker(TrackerConfig{ACKTimeout: time.Minute})

	tr.Track(0xAAAA, PendingACK{})
	tr.Track(0xBBBB, PendingACK{})
	tr.Track(0xCCCC, PendingACK{})

	if tr.PendingCount() != 3 {
		t.Errorf("PendingCount = %d, want 3", tr.PendingCount())
	}

	tr.Resolve(0xBBBB)
	if tr.PendingCount() != 2 {
		t.Errorf("PendingCount = %d, want 2", tr.PendingCount())
	}

	tr.Cancel(0xAAAA)
	if tr.PendingCount() != 1 {
		t.Errorf("PendingCount = %d, want 1", tr.PendingCount())
	}
}

func TestTracker_Timeout_NilCallbacks(t *testing.T) {
	tr := NewTracker(TrackerConfig{
		ACKTimeout: 100 * time.Millisecond,
		MaxRetries: 0,
	})

	now := time.Now()
	tr.nowFn = func() time.Time { return now }

	// No callbacks at all — should not panic
	tr.Track(0x4444, PendingACK{})

	now = now.Add(200 * time.Millisecond)
	tr.checkTimeouts() // should not panic

	if tr.PendingCount() != 0 {
		t.Errorf("PendingCount = %d, want 0", tr.PendingCount())
	}
}

func TestTracker_NoRetry_WithoutResend(t *testing.T) {
	tr := NewTracker(TrackerConfig{
		ACKTimeout: 100 * time.Millisecond,
		MaxRetries: 3, // retries configured but no Resend function
	})

	now := time.Now()
	tr.nowFn = func() time.Time { return now }

	var timedOut atomic.Bool
	tr.Track(0x5555, PendingACK{
		OnTimeout: func() { timedOut.Store(true) },
		// Resend is nil → should go straight to timeout
	})

	now = now.Add(200 * time.Millisecond)
	tr.checkTimeouts()

	if !timedOut.Load() {
		t.Error("should timeout immediately when Resend is nil")
	}
}

func TestTracker_Stop(t *testing.T) {
	tr := NewTracker(TrackerConfig{ACKTimeout: time.Minute})

	done := make(chan struct{})
	go func() {
		tr.Start(context.Background())
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	tr.Stop()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("tracker did not stop within timeout")
	}
}

func TestTracker_Stop_Context(t *testing.T) {
	tr := NewTracker(TrackerConfig{ACKTimeout: time.Minute})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		tr.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("tracker did not stop within timeout")
	}
}
