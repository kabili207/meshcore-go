package codec

import "testing"

func TestPathInfoFromWireByte_Mode0(t *testing.T) {
	// Mode 0: 1-byte hashes. Wire byte == hop count for values 0-63.
	for hops := uint8(0); hops <= MaxHopCount; hops++ {
		info := PathInfoFromWireByte(hops)
		if info.HashSize != 1 {
			t.Errorf("hops=%d: HashSize = %d, want 1", hops, info.HashSize)
		}
		if info.HopCount != hops {
			t.Errorf("hops=%d: HopCount = %d, want %d", hops, info.HopCount, hops)
		}
		if info.ByteLen() != int(hops) {
			t.Errorf("hops=%d: ByteLen = %d, want %d", hops, info.ByteLen(), hops)
		}
	}
}

func TestPathInfoFromWireByte_Mode1(t *testing.T) {
	// Mode 1: 2-byte hashes. Upper 2 bits = 01.
	wire := uint8(0x40 | 5) // mode 1, 5 hops
	info := PathInfoFromWireByte(wire)
	if info.HashSize != 2 {
		t.Errorf("HashSize = %d, want 2", info.HashSize)
	}
	if info.HopCount != 5 {
		t.Errorf("HopCount = %d, want 5", info.HopCount)
	}
	if info.ByteLen() != 10 {
		t.Errorf("ByteLen = %d, want 10", info.ByteLen())
	}
}

func TestPathInfoFromWireByte_Mode2(t *testing.T) {
	// Mode 2: 3-byte hashes. Upper 2 bits = 10.
	wire := uint8(0x80 | 7) // mode 2, 7 hops
	info := PathInfoFromWireByte(wire)
	if info.HashSize != 3 {
		t.Errorf("HashSize = %d, want 3", info.HashSize)
	}
	if info.HopCount != 7 {
		t.Errorf("HopCount = %d, want 7", info.HopCount)
	}
	if info.ByteLen() != 21 {
		t.Errorf("ByteLen = %d, want 21", info.ByteLen())
	}
}

func TestPathInfoFromWireByte_ZeroHops(t *testing.T) {
	tests := []struct {
		name     string
		wire     uint8
		hashSize uint8
	}{
		{"mode0", 0x00, 1},
		{"mode1", 0x40, 2},
		{"mode2", 0x80, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info := PathInfoFromWireByte(tc.wire)
			if info.HashSize != tc.hashSize {
				t.Errorf("HashSize = %d, want %d", info.HashSize, tc.hashSize)
			}
			if info.HopCount != 0 {
				t.Errorf("HopCount = %d, want 0", info.HopCount)
			}
			if info.ByteLen() != 0 {
				t.Errorf("ByteLen = %d, want 0", info.ByteLen())
			}
		})
	}
}

func TestPathInfoFromWireByte_MaxHops(t *testing.T) {
	tests := []struct {
		name     string
		wire     uint8
		hashSize uint8
		byteLen  int
	}{
		{"mode0_max", 0x00 | MaxHopCount, 1, 63},
		{"mode1_max", 0x40 | MaxHopCount, 2, 126},
		{"mode2_max", 0x80 | MaxHopCount, 3, 189},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info := PathInfoFromWireByte(tc.wire)
			if info.HashSize != tc.hashSize {
				t.Errorf("HashSize = %d, want %d", info.HashSize, tc.hashSize)
			}
			if info.HopCount != MaxHopCount {
				t.Errorf("HopCount = %d, want %d", info.HopCount, MaxHopCount)
			}
			if info.ByteLen() != tc.byteLen {
				t.Errorf("ByteLen = %d, want %d", info.ByteLen(), tc.byteLen)
			}
		})
	}
}

func TestPathInfo_RoundTrip(t *testing.T) {
	tests := []struct {
		hashSize uint8
		hopCount uint8
	}{
		{1, 0}, {1, 1}, {1, 10}, {1, MaxHopCount},
		{2, 0}, {2, 1}, {2, 10}, {2, MaxHopCount},
		{3, 0}, {3, 1}, {3, 10}, {3, MaxHopCount},
	}
	for _, tc := range tests {
		info := PathInfo{HashSize: tc.hashSize, HopCount: tc.hopCount}
		wire := info.ToWireByte()
		decoded := PathInfoFromWireByte(wire)
		if decoded.HashSize != tc.hashSize {
			t.Errorf("HashSize=%d,HopCount=%d: round-trip HashSize = %d",
				tc.hashSize, tc.hopCount, decoded.HashSize)
		}
		if decoded.HopCount != tc.hopCount {
			t.Errorf("HashSize=%d,HopCount=%d: round-trip HopCount = %d",
				tc.hashSize, tc.hopCount, decoded.HopCount)
		}
	}
}

func TestPathInfo_Mode0BackwardCompat(t *testing.T) {
	// For mode 0, the wire byte must equal the hop count.
	// This ensures backward compatibility with pre-1.14 firmware.
	for hops := uint8(0); hops <= MaxHopCount; hops++ {
		info := PathInfo{HashSize: 1, HopCount: hops}
		wire := info.ToWireByte()
		if wire != hops {
			t.Errorf("mode 0 hops=%d: wire byte = 0x%02x, want 0x%02x", hops, wire, hops)
		}
	}
}

func TestPathInfo_Mode3Rejected(t *testing.T) {
	// Wire byte 0xC0 | N would decode to HashSize=4, which is reserved.
	// The firmware rejects mode 3. We should still decode it consistently
	// (HashSize=4) so callers can check and reject.
	wire := uint8(0xC0 | 3)
	info := PathInfoFromWireByte(wire)
	if info.HashSize != 4 {
		t.Errorf("mode 3: HashSize = %d, want 4", info.HashSize)
	}
	if info.HopCount != 3 {
		t.Errorf("mode 3: HopCount = %d, want 3", info.HopCount)
	}
}
