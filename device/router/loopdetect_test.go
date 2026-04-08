package router

import "testing"

func TestDetectLoop_Off(t *testing.T) {
	self := []byte{0xAA}
	path := []byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA}
	if detectLoop(path, self, 1, LoopDetectOff) {
		t.Error("LoopDetectOff should never detect a loop")
	}
}

func TestDetectLoop_1ByteHash(t *testing.T) {
	self := []byte{0xAA}

	tests := []struct {
		name  string
		path  []byte
		level int
		want  bool
	}{
		// Minimal: threshold 4 for 1-byte hashes
		{"minimal_3x", []byte{0xAA, 0xBB, 0xAA, 0xCC, 0xAA}, LoopDetectMinimal, false},
		{"minimal_4x", []byte{0xAA, 0xBB, 0xAA, 0xAA, 0xAA}, LoopDetectMinimal, true},

		// Moderate: threshold 2 for 1-byte hashes
		{"moderate_1x", []byte{0xAA, 0xBB, 0xCC}, LoopDetectModerate, false},
		{"moderate_2x", []byte{0xAA, 0xBB, 0xAA}, LoopDetectModerate, true},

		// Strict: threshold 1 for 1-byte hashes
		{"strict_0x", []byte{0xBB, 0xCC, 0xDD}, LoopDetectStrict, false},
		{"strict_1x", []byte{0xBB, 0xAA, 0xCC}, LoopDetectStrict, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detectLoop(tc.path, self, 1, tc.level)
			if got != tc.want {
				t.Errorf("detectLoop() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetectLoop_2ByteHash(t *testing.T) {
	self := []byte{0xAA, 0xBB}

	tests := []struct {
		name  string
		path  []byte
		level int
		want  bool
	}{
		// Minimal: threshold 2 for 2-byte hashes
		{"minimal_1x", []byte{0xAA, 0xBB, 0xCC, 0xDD}, LoopDetectMinimal, false},
		{"minimal_2x", []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB}, LoopDetectMinimal, true},

		// Moderate: threshold 1 for 2-byte hashes
		{"moderate_0x", []byte{0xCC, 0xDD, 0xEE, 0xFF}, LoopDetectModerate, false},
		{"moderate_1x", []byte{0xAA, 0xBB, 0xCC, 0xDD}, LoopDetectModerate, true},

		// Strict: threshold 1 for 2-byte hashes
		{"strict_0x", []byte{0xCC, 0xDD}, LoopDetectStrict, false},
		{"strict_1x", []byte{0xAA, 0xBB}, LoopDetectStrict, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detectLoop(tc.path, self, 2, tc.level)
			if got != tc.want {
				t.Errorf("detectLoop() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetectLoop_3ByteHash(t *testing.T) {
	self := []byte{0xAA, 0xBB, 0xCC}

	tests := []struct {
		name  string
		path  []byte
		level int
		want  bool
	}{
		// All modes have threshold 1 for 3-byte hashes
		{"minimal_0x", []byte{0x11, 0x22, 0x33}, LoopDetectMinimal, false},
		{"minimal_1x", []byte{0xAA, 0xBB, 0xCC}, LoopDetectMinimal, true},
		{"moderate_1x", []byte{0xAA, 0xBB, 0xCC}, LoopDetectModerate, true},
		{"strict_1x", []byte{0xAA, 0xBB, 0xCC}, LoopDetectStrict, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detectLoop(tc.path, self, 3, tc.level)
			if got != tc.want {
				t.Errorf("detectLoop() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetectLoop_EmptyPath(t *testing.T) {
	self := []byte{0xAA}
	if detectLoop(nil, self, 1, LoopDetectStrict) {
		t.Error("empty path should not loop")
	}
	if detectLoop([]byte{}, self, 1, LoopDetectStrict) {
		t.Error("empty path should not loop")
	}
}

func TestDetectLoop_InvalidLevel(t *testing.T) {
	self := []byte{0xAA}
	path := []byte{0xAA, 0xAA, 0xAA}
	if detectLoop(path, self, 1, -1) {
		t.Error("invalid level should not loop")
	}
	if detectLoop(path, self, 1, 4) {
		t.Error("invalid level should not loop")
	}
}
