package clock

import (
	"sync/atomic"
	"testing"
)

// mockClock creates a Clock with a controllable time source.
func mockClock(initial uint32) (*Clock, *atomic.Uint32) {
	var t atomic.Uint32
	t.Store(initial)
	c := &Clock{
		nowFn: func() uint32 { return t.Load() },
	}
	return c, &t
}

func TestGetCurrentTime(t *testing.T) {
	c, now := mockClock(1000)
	if got := c.GetCurrentTime(); got != 1000 {
		t.Errorf("GetCurrentTime() = %d, want 1000", got)
	}
	now.Store(2000)
	if got := c.GetCurrentTime(); got != 2000 {
		t.Errorf("GetCurrentTime() = %d, want 2000", got)
	}
}

func TestGetCurrentTimeUnique_Advancing(t *testing.T) {
	c, now := mockClock(100)

	// Each call with advancing clock returns the real time.
	if got := c.GetCurrentTimeUnique(); got != 100 {
		t.Errorf("got %d, want 100", got)
	}
	now.Store(101)
	if got := c.GetCurrentTimeUnique(); got != 101 {
		t.Errorf("got %d, want 101", got)
	}
	now.Store(105)
	if got := c.GetCurrentTimeUnique(); got != 105 {
		t.Errorf("got %d, want 105", got)
	}
}

func TestGetCurrentTimeUnique_SameSecond(t *testing.T) {
	c, _ := mockClock(100)

	// Multiple calls within the same second should still increase.
	v1 := c.GetCurrentTimeUnique()
	v2 := c.GetCurrentTimeUnique()
	v3 := c.GetCurrentTimeUnique()

	if v2 <= v1 {
		t.Errorf("v2 (%d) should be > v1 (%d)", v2, v1)
	}
	if v3 <= v2 {
		t.Errorf("v3 (%d) should be > v2 (%d)", v3, v2)
	}
}

func TestGetCurrentTimeUnique_StrictlyIncreasing(t *testing.T) {
	c, now := mockClock(100)

	// Rapid calls followed by a time advance.
	v1 := c.GetCurrentTimeUnique() // 100
	v2 := c.GetCurrentTimeUnique() // 101 (bumped)
	v3 := c.GetCurrentTimeUnique() // 102 (bumped)

	now.Store(200)
	v4 := c.GetCurrentTimeUnique() // 200 (clock jumped ahead)

	vals := []uint32{v1, v2, v3, v4}
	for i := 1; i < len(vals); i++ {
		if vals[i] <= vals[i-1] {
			t.Errorf("not strictly increasing at index %d: %d <= %d", i, vals[i], vals[i-1])
		}
	}
}

func TestGetCurrentTimeUnique_ClockGoesBackward(t *testing.T) {
	c, now := mockClock(200)

	v1 := c.GetCurrentTimeUnique() // 200

	// Simulate clock going backward (e.g., NTP adjustment).
	now.Store(150)
	v2 := c.GetCurrentTimeUnique() // 201 (bumped, ignores backward clock)

	if v2 <= v1 {
		t.Errorf("v2 (%d) should be > v1 (%d) even when clock goes backward", v2, v1)
	}
}

func TestGetCurrentTimeUnique_ZeroStart(t *testing.T) {
	c, _ := mockClock(0)

	// With clock at 0 (unset) and lastUnique at 0: t(0) <= lastUnique(0) is true,
	// so firmware bumps to 1. This matches MeshCore behavior.
	v1 := c.GetCurrentTimeUnique()
	if v1 != 1 {
		t.Errorf("first call with clock=0: got %d, want 1", v1)
	}

	v2 := c.GetCurrentTimeUnique()
	if v2 <= v1 {
		t.Errorf("v2 (%d) should be > v1 (%d)", v2, v1)
	}
}

func TestSetCurrentTime(t *testing.T) {
	c := New()
	c.SetCurrentTime(1700000000)

	got := c.GetCurrentTime()
	// Should be very close to what we set (within 1 second).
	if got < 1700000000 || got > 1700000001 {
		t.Errorf("GetCurrentTime() after set = %d, want ~1700000000", got)
	}
}

func TestSetCurrentTime_UniqueStillWorks(t *testing.T) {
	c, _ := mockClock(500)

	// Get a value at 500.
	c.GetCurrentTimeUnique() // 500

	// Override the clock source.
	c.SetCurrentTime(1000)

	v := c.GetCurrentTimeUnique()
	if v < 1000 {
		t.Errorf("after SetCurrentTime(1000), GetCurrentTimeUnique() = %d, want >= 1000", v)
	}
}

func TestNew_ReturnsReasonableTime(t *testing.T) {
	c := New()
	got := c.GetCurrentTime()
	// Should be a reasonable UNIX timestamp (after 2020).
	if got < 1577836800 {
		t.Errorf("GetCurrentTime() = %d, expected > 1577836800 (2020-01-01)", got)
	}
}
