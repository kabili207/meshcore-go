package clock

import (
	"sync"
	"time"
)

// Clock provides timestamp generation matching MeshCore's RTCClock.
// GetCurrentTimeUnique returns strictly increasing uint32 UNIX epoch values,
// even when called multiple times within the same second.
type Clock struct {
	mu         sync.Mutex
	lastUnique uint32
	nowFn      func() uint32 // overridable for testing
}

// New creates a Clock that uses the system clock.
func New() *Clock {
	return &Clock{
		nowFn: func() uint32 {
			return uint32(time.Now().Unix())
		},
	}
}

// GetCurrentTime returns the current UNIX epoch time as uint32.
func (c *Clock) GetCurrentTime() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nowFn()
}

// SetCurrentTime overrides the clock source with a fixed value.
// Useful for bootstrapping from contact timestamps or external time sources.
// Subsequent calls to GetCurrentTime and GetCurrentTimeUnique will use this
// value as a base, advancing monotonically from it.
func (c *Clock) SetCurrentTime(t uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	offset := t
	c.nowFn = func() uint32 {
		// Advance by wall-clock delta from the moment SetCurrentTime was called.
		elapsed := uint32(time.Since(time.Now()).Seconds())
		return offset + elapsed
	}
	// For a simple set, just use a fixed base that advances with real time.
	base := time.Now()
	c.nowFn = func() uint32 {
		return offset + uint32(time.Since(base).Seconds())
	}
}

// GetCurrentTimeUnique returns a strictly increasing timestamp.
// If the real clock hasn't advanced past the last returned value,
// the internal counter is bumped by 1. This matches MeshCore's
// RTCClock::getCurrentTimeUnique() behavior.
func (c *Clock) GetCurrentTimeUnique() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.nowFn()
	if t <= c.lastUnique {
		c.lastUnique++
		return c.lastUnique
	}
	c.lastUnique = t
	return t
}
