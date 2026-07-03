package node

import "sync"

// rateLimiter allows up to max events per rolling window of windowSecs seconds.
// It mirrors the firmware's RateLimiter: the window resets on the first event
// after it expires, and events beyond the cap within a window are denied.
type rateLimiter struct {
	mu          sync.Mutex
	max         uint16
	windowSecs  uint32
	windowStart uint32
	count       uint16
}

func newRateLimiter(max uint16, windowSecs uint32) *rateLimiter {
	return &rateLimiter{max: max, windowSecs: windowSecs}
}

// allow reports whether an event is permitted at time now (seconds since epoch
// on the node's clock), counting it against the current window.
func (r *rateLimiter) allow(now uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if now < r.windowStart+r.windowSecs {
		r.count++
		if r.count > r.max {
			return false
		}
	} else {
		r.windowStart = now
		r.count = 1
	}
	return true
}
