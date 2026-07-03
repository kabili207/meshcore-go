package node

import "testing"

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(2, 100)

	if !rl.allow(1000) {
		t.Error("1st event should be allowed")
	}
	if !rl.allow(1010) {
		t.Error("2nd event should be allowed")
	}
	if rl.allow(1020) {
		t.Error("3rd event within the window should be denied")
	}
	// Window (100s) has passed since it started at 1000; a new window opens.
	if !rl.allow(1100) {
		t.Error("event after the window should be allowed")
	}
	if !rl.allow(1150) {
		t.Error("2nd event in the new window should be allowed")
	}
	if rl.allow(1180) {
		t.Error("3rd event in the new window should be denied")
	}
}
