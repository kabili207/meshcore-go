package multipart

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core/codec"
)

func TestParseFragment(t *testing.T) {
	// remaining=2, innerType=ACK(3), data=[0xAA, 0xBB, 0xCC, 0xDD]
	payload := []byte{(2 << 4) | codec.PayloadTypeAck, 0xAA, 0xBB, 0xCC, 0xDD}
	frag, err := ParseFragment(payload)
	if err != nil {
		t.Fatalf("ParseFragment failed: %v", err)
	}

	if frag.Remaining != 2 {
		t.Errorf("Remaining = %d, want 2", frag.Remaining)
	}
	if frag.InnerType != codec.PayloadTypeAck {
		t.Errorf("InnerType = %d, want %d", frag.InnerType, codec.PayloadTypeAck)
	}
	if len(frag.Data) != 4 {
		t.Errorf("Data length = %d, want 4", len(frag.Data))
	}
}

func TestParseFragment_Empty(t *testing.T) {
	_, err := ParseFragment([]byte{})
	if err == nil {
		t.Error("expected error for empty payload")
	}
}

func TestReassembler_SingleFragment(t *testing.T) {
	r := New()

	// A single-fragment multipart (remaining=0)
	ackData := make([]byte, 4)
	binary.LittleEndian.PutUint32(ackData, 0x12345678)

	frag := &Fragment{
		Remaining: 0,
		InnerType: codec.PayloadTypeAck,
		Data:      ackData,
	}

	pkt := r.HandleFragment(frag, 0xAA)
	if pkt == nil {
		t.Fatal("expected assembled packet for single fragment")
	}

	if pkt.PayloadType() != codec.PayloadTypeAck {
		t.Errorf("inner type = %d, want %d", pkt.PayloadType(), codec.PayloadTypeAck)
	}
	if len(pkt.Payload) != 4 {
		t.Fatalf("payload length = %d, want 4", len(pkt.Payload))
	}

	got := binary.LittleEndian.Uint32(pkt.Payload)
	if got != 0x12345678 {
		t.Errorf("ACK value = %08x, want 12345678", got)
	}
}

func TestReassembler_TwoFragments(t *testing.T) {
	r := New()

	// Fragment 1: remaining=1 (one more to come)
	frag1 := &Fragment{
		Remaining: 1,
		InnerType: codec.PayloadTypeAck,
		Data:      []byte{0x78, 0x56},
	}

	// Fragment 2: remaining=0 (final)
	frag2 := &Fragment{
		Remaining: 0,
		InnerType: codec.PayloadTypeAck,
		Data:      []byte{0x34, 0x12},
	}

	pkt := r.HandleFragment(frag1, 0xBB)
	if pkt != nil {
		t.Error("should not return packet after first fragment")
	}
	if r.PendingCount() != 1 {
		t.Errorf("pending = %d, want 1", r.PendingCount())
	}

	pkt = r.HandleFragment(frag2, 0xBB)
	if pkt == nil {
		t.Fatal("expected assembled packet after final fragment")
	}
	if r.PendingCount() != 0 {
		t.Errorf("pending = %d, want 0 after assembly", r.PendingCount())
	}

	// Concatenated data
	if len(pkt.Payload) != 4 {
		t.Fatalf("payload length = %d, want 4", len(pkt.Payload))
	}
	want := []byte{0x78, 0x56, 0x34, 0x12}
	for i, b := range want {
		if pkt.Payload[i] != b {
			t.Errorf("payload[%d] = %02x, want %02x", i, pkt.Payload[i], b)
		}
	}
}

func TestReassembler_ThreeFragments(t *testing.T) {
	r := New()

	frags := []*Fragment{
		{Remaining: 2, InnerType: codec.PayloadTypeTxtMsg, Data: []byte("hel")},
		{Remaining: 1, InnerType: codec.PayloadTypeTxtMsg, Data: []byte("lo ")},
		{Remaining: 0, InnerType: codec.PayloadTypeTxtMsg, Data: []byte("world")},
	}

	for i, f := range frags[:2] {
		pkt := r.HandleFragment(f, 0x01)
		if pkt != nil {
			t.Errorf("should not return packet after fragment %d", i)
		}
	}

	pkt := r.HandleFragment(frags[2], 0x01)
	if pkt == nil {
		t.Fatal("expected assembled packet after final fragment")
	}

	if string(pkt.Payload) != "hello world" {
		t.Errorf("payload = %q, want %q", pkt.Payload, "hello world")
	}
	if pkt.PayloadType() != codec.PayloadTypeTxtMsg {
		t.Errorf("inner type = %d, want %d", pkt.PayloadType(), codec.PayloadTypeTxtMsg)
	}
}

func TestReassembler_DifferentSenders(t *testing.T) {
	r := New()

	// Two different senders sending ACK fragments simultaneously
	fragA := &Fragment{Remaining: 1, InnerType: codec.PayloadTypeAck, Data: []byte{0xAA, 0xAA}}
	fragB := &Fragment{Remaining: 1, InnerType: codec.PayloadTypeAck, Data: []byte{0xBB, 0xBB}}

	r.HandleFragment(fragA, 0x01) // sender 1
	r.HandleFragment(fragB, 0x02) // sender 2

	if r.PendingCount() != 2 {
		t.Errorf("pending = %d, want 2", r.PendingCount())
	}

	// Complete sender 1
	fragA2 := &Fragment{Remaining: 0, InnerType: codec.PayloadTypeAck, Data: []byte{0xCC, 0xCC}}
	pkt := r.HandleFragment(fragA2, 0x01)
	if pkt == nil {
		t.Fatal("expected packet for sender 1")
	}
	if r.PendingCount() != 1 {
		t.Errorf("pending = %d, want 1", r.PendingCount())
	}

	// Complete sender 2
	fragB2 := &Fragment{Remaining: 0, InnerType: codec.PayloadTypeAck, Data: []byte{0xDD, 0xDD}}
	pkt = r.HandleFragment(fragB2, 0x02)
	if pkt == nil {
		t.Fatal("expected packet for sender 2")
	}
	if r.PendingCount() != 0 {
		t.Errorf("pending = %d, want 0", r.PendingCount())
	}
}

func TestReassembler_Timeout(t *testing.T) {
	r := NewWithTimeout(50 * time.Millisecond)

	frag := &Fragment{Remaining: 1, InnerType: codec.PayloadTypeAck, Data: []byte{0x01}}
	r.HandleFragment(frag, 0xCC)

	if r.PendingCount() != 1 {
		t.Errorf("pending = %d, want 1", r.PendingCount())
	}

	time.Sleep(60 * time.Millisecond)

	// Next call triggers expiration
	frag2 := &Fragment{Remaining: 0, InnerType: codec.PayloadTypeTxtMsg, Data: []byte{0x02}}
	r.HandleFragment(frag2, 0xDD)

	// The old entry should have been expired
	if r.PendingCount() != 0 {
		t.Errorf("pending = %d, want 0 after expiry", r.PendingCount())
	}
}

func TestReassembler_Clear(t *testing.T) {
	r := New()

	frag := &Fragment{Remaining: 1, InnerType: codec.PayloadTypeAck, Data: []byte{0x01}}
	r.HandleFragment(frag, 0xAA)

	r.Clear()
	if r.PendingCount() != 0 {
		t.Errorf("pending = %d, want 0 after clear", r.PendingCount())
	}
}

func TestBuildAndParseMultipart_RoundTrip(t *testing.T) {
	ackData := make([]byte, 4)
	binary.LittleEndian.PutUint32(ackData, 0xDEADBEEF)

	// Build a multipart payload
	payload := codec.BuildMultipartPayload(1, codec.PayloadTypeAck, ackData)

	// Parse it back
	frag, err := ParseFragment(payload)
	if err != nil {
		t.Fatalf("ParseFragment failed: %v", err)
	}

	if frag.Remaining != 1 {
		t.Errorf("Remaining = %d, want 1", frag.Remaining)
	}
	if frag.InnerType != codec.PayloadTypeAck {
		t.Errorf("InnerType = %d, want %d", frag.InnerType, codec.PayloadTypeAck)
	}

	got := binary.LittleEndian.Uint32(frag.Data)
	if got != 0xDEADBEEF {
		t.Errorf("ACK value = %08x, want DEADBEEF", got)
	}
}
