package codec

import (
	"testing"
)

func TestParseTracePayload(t *testing.T) {
	pathHashes := []byte{0xAA, 0xBB, 0xCC}
	data := BuildTracePayload(0x12345678, 0xAABBCCDD, 0x00, pathHashes)

	tp, err := ParseTracePayload(data)
	if err != nil {
		t.Fatalf("ParseTracePayload() error = %v", err)
	}
	if tp.Tag != 0x12345678 {
		t.Errorf("Tag = %08x, want 0x12345678", tp.Tag)
	}
	if tp.AuthCode != 0xAABBCCDD {
		t.Errorf("AuthCode = %08x, want 0xAABBCCDD", tp.AuthCode)
	}
	if tp.Flags != 0x00 {
		t.Errorf("Flags = %02x, want 0x00", tp.Flags)
	}
	if tp.HashSize != 1 {
		t.Errorf("HashSize = %d, want 1", tp.HashSize)
	}
	if len(tp.PathHashes) != 3 {
		t.Errorf("PathHashes len = %d, want 3", len(tp.PathHashes))
	}
}

func TestParseTracePayload_TooShort(t *testing.T) {
	data := make([]byte, 5) // less than TraceHeaderSize
	_, err := ParseTracePayload(data)
	if err == nil {
		t.Error("expected error for short payload")
	}
}

func TestParseTracePayload_HeaderOnly(t *testing.T) {
	data := BuildTracePayload(1, 2, 0, nil)
	tp, err := ParseTracePayload(data)
	if err != nil {
		t.Fatalf("ParseTracePayload() error = %v", err)
	}
	if len(tp.PathHashes) != 0 {
		t.Errorf("PathHashes len = %d, want 0", len(tp.PathHashes))
	}
	if tp.HopCount() != 0 {
		t.Errorf("HopCount() = %d, want 0", tp.HopCount())
	}
}

func TestTracePayload_HopCount(t *testing.T) {
	tests := []struct {
		name       string
		flags      uint8
		hashesLen  int
		wantHops   int
	}{
		{"1-byte hashes, 3 hops", 0x00, 3, 3},
		{"2-byte hashes, 3 hops", 0x01, 6, 3},
		{"4-byte hashes, 2 hops", 0x02, 8, 2},
		{"1-byte hashes, 0 hops", 0x00, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashes := make([]byte, tt.hashesLen)
			data := BuildTracePayload(0, 0, tt.flags, hashes)
			tp, err := ParseTracePayload(data)
			if err != nil {
				t.Fatalf("ParseTracePayload() error = %v", err)
			}
			if got := tp.HopCount(); got != tt.wantHops {
				t.Errorf("HopCount() = %d, want %d", got, tt.wantHops)
			}
		})
	}
}

func TestTracePayload_HashAt(t *testing.T) {
	// 2-byte hashes: [0xAA, 0xBB], [0xCC, 0xDD]
	hashes := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	data := BuildTracePayload(0, 0, 0x01, hashes) // flags=1 → 2-byte hashes
	tp, err := ParseTracePayload(data)
	if err != nil {
		t.Fatalf("ParseTracePayload() error = %v", err)
	}

	h0 := tp.HashAt(0)
	if h0[0] != 0xAA || h0[1] != 0xBB {
		t.Errorf("HashAt(0) = %v, want [AA BB]", h0)
	}

	h1 := tp.HashAt(1)
	if h1[0] != 0xCC || h1[1] != 0xDD {
		t.Errorf("HashAt(1) = %v, want [CC DD]", h1)
	}

	if h2 := tp.HashAt(2); h2 != nil {
		t.Errorf("HashAt(2) = %v, want nil (out of range)", h2)
	}
}

func TestBuildTracePayload_RoundTrip(t *testing.T) {
	tag := uint32(0xDEADBEEF)
	auth := uint32(0xCAFEBABE)
	flags := uint8(0x02) // 4-byte hashes
	hashes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	data := BuildTracePayload(tag, auth, flags, hashes)
	tp, err := ParseTracePayload(data)
	if err != nil {
		t.Fatalf("ParseTracePayload() error = %v", err)
	}

	if tp.Tag != tag {
		t.Errorf("Tag = %08x, want %08x", tp.Tag, tag)
	}
	if tp.AuthCode != auth {
		t.Errorf("AuthCode = %08x, want %08x", tp.AuthCode, auth)
	}
	if tp.Flags != flags {
		t.Errorf("Flags = %02x, want %02x", tp.Flags, flags)
	}
	if tp.HashSize != 4 {
		t.Errorf("HashSize = %d, want 4", tp.HashSize)
	}
	if tp.HopCount() != 2 {
		t.Errorf("HopCount() = %d, want 2", tp.HopCount())
	}
}

func TestBuildTracePayload_FullStack(t *testing.T) {
	tag := uint32(0x11223344)
	auth := uint32(0x55667788)
	hashes := []byte{0xAA, 0xBB, 0xCC}
	payload := BuildTracePayload(tag, auth, 0x00, hashes)

	// Wrap in a packet
	pkt := &Packet{
		Header:  (PayloadTypeTrace << PHTypeShift) | RouteTypeDirect,
		Payload: payload,
	}

	// Encode to wire
	wire := pkt.WriteTo()

	// Decode from wire
	var pkt2 Packet
	if err := pkt2.ReadFrom(wire); err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}

	// Parse the payload
	tp, err := ParseTracePayload(pkt2.Payload)
	if err != nil {
		t.Fatalf("ParseTracePayload() error = %v", err)
	}

	if tp.Tag != tag {
		t.Errorf("Tag = %08x, want %08x", tp.Tag, tag)
	}
	if tp.HopCount() != 3 {
		t.Errorf("HopCount() = %d, want 3", tp.HopCount())
	}
}
