package router

import (
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core/codec"
)

func makeTestPacket(payloadType uint8) *codec.Packet {
	return &codec.Packet{
		Header:  (payloadType << codec.PHTypeShift) | codec.RouteTypeFlood,
		Payload: []byte{0x01, 0x02},
	}
}

func TestSendQueue_Empty(t *testing.T) {
	q := NewSendQueue()
	if pkt := q.Pop(); pkt != nil {
		t.Error("expected nil from empty queue")
	}
	if q.Len() != 0 {
		t.Errorf("Len() = %d, want 0", q.Len())
	}
}

func TestSendQueue_SingleItem(t *testing.T) {
	q := NewSendQueue()
	pkt := makeTestPacket(codec.PayloadTypeTxtMsg)
	q.Push(pkt, 0, 0)

	if q.Len() != 1 {
		t.Errorf("Len() = %d, want 1", q.Len())
	}

	got := q.Pop()
	if got != pkt {
		t.Error("expected to get the same packet back")
	}
	if q.Len() != 0 {
		t.Errorf("Len() = %d after pop, want 0", q.Len())
	}
}

func TestSendQueue_PriorityOrdering(t *testing.T) {
	q := NewSendQueue()
	low := makeTestPacket(codec.PayloadTypeAdvert)
	mid := makeTestPacket(codec.PayloadTypeTxtMsg)
	high := makeTestPacket(codec.PayloadTypeAck)

	// Push in reverse priority order
	q.Push(low, 3, 0)
	q.Push(mid, 1, 0)
	q.Push(high, 0, 0)

	// Should dequeue highest priority (0) first
	if got := q.Pop(); got != high {
		t.Error("first pop should return priority 0 packet")
	}
	if got := q.Pop(); got != mid {
		t.Error("second pop should return priority 1 packet")
	}
	if got := q.Pop(); got != low {
		t.Error("third pop should return priority 3 packet")
	}
}

func TestSendQueue_DelayedItems(t *testing.T) {
	q := NewSendQueue()
	delayed := makeTestPacket(codec.PayloadTypeTxtMsg)
	ready := makeTestPacket(codec.PayloadTypeAck)

	q.Push(delayed, 0, 100*time.Millisecond) // high priority but delayed
	q.Push(ready, 5, 0)                       // low priority but ready now

	// The delayed item shouldn't be returned yet
	got := q.Pop()
	if got != ready {
		t.Error("should return the ready item, not the delayed one")
	}

	// Nothing else ready
	if got := q.Pop(); got != nil {
		t.Error("delayed item should not be ready yet")
	}

	// Wait for the delay
	time.Sleep(110 * time.Millisecond)

	got = q.Pop()
	if got != delayed {
		t.Error("delayed item should be ready now")
	}
}

func TestSendQueue_FIFOWithinPriority(t *testing.T) {
	q := NewSendQueue()
	first := makeTestPacket(codec.PayloadTypeTxtMsg)
	second := makeTestPacket(codec.PayloadTypeAck)

	q.Push(first, 1, 0)
	q.Push(second, 1, 0)

	// Same priority: first-inserted should come out first
	if got := q.Pop(); got != first {
		t.Error("should return first-inserted item when priorities are equal")
	}
	if got := q.Pop(); got != second {
		t.Error("should return second-inserted item")
	}
}
