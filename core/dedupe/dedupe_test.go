package dedupe

import (
	"encoding/binary"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
)

func makePacket(payloadType uint8, payload []byte) *codec.Packet {
	return &codec.Packet{
		Header:  (payloadType << codec.PHTypeShift) | codec.RouteTypeFlood,
		Payload: payload,
	}
}

func makeAckPacket(checksum uint32) *codec.Packet {
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint32(payload, checksum)
	return makePacket(codec.PayloadTypeAck, payload)
}

func TestHasSeen_NewPacket(t *testing.T) {
	d := New()
	pkt := makePacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02, 0x03})

	if d.HasSeen(pkt) {
		t.Error("new packet should not be marked as seen")
	}
}

func TestHasSeen_DuplicatePacket(t *testing.T) {
	d := New()
	pkt := makePacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02, 0x03})

	d.HasSeen(pkt) // first time
	if !d.HasSeen(pkt) {
		t.Error("duplicate packet should be marked as seen")
	}
}

func TestHasSeen_DifferentPayload(t *testing.T) {
	d := New()
	pkt1 := makePacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02, 0x03})
	pkt2 := makePacket(codec.PayloadTypeTxtMsg, []byte{0x04, 0x05, 0x06})

	d.HasSeen(pkt1)
	if d.HasSeen(pkt2) {
		t.Error("different packet should not be marked as seen")
	}
}

func TestHasSeen_DifferentType(t *testing.T) {
	d := New()
	payload := []byte{0x01, 0x02, 0x03}
	pkt1 := makePacket(codec.PayloadTypeTxtMsg, payload)
	pkt2 := makePacket(codec.PayloadTypeGrpTxt, payload)

	d.HasSeen(pkt1)
	if d.HasSeen(pkt2) {
		t.Error("same payload but different type should not be seen")
	}
}

func TestHasSeen_AckPacket(t *testing.T) {
	d := New()
	ack := makeAckPacket(0x12345678)

	if d.HasSeen(ack) {
		t.Error("new ACK should not be marked as seen")
	}
	if !d.HasSeen(ack) {
		t.Error("duplicate ACK should be marked as seen")
	}
}

func TestHasSeen_DifferentAcks(t *testing.T) {
	d := New()
	ack1 := makeAckPacket(0x11111111)
	ack2 := makeAckPacket(0x22222222)

	d.HasSeen(ack1)
	if d.HasSeen(ack2) {
		t.Error("different ACK should not be marked as seen")
	}
}

func TestHasSeen_CircularOverwrite(t *testing.T) {
	d := NewWithCapacity(4, 4)

	// Fill up the hash table
	for i := range 4 {
		pkt := makePacket(codec.PayloadTypeTxtMsg, []byte{byte(i)})
		d.HasSeen(pkt)
	}

	// The first entry should still be seen
	first := makePacket(codec.PayloadTypeTxtMsg, []byte{0x00})
	if !d.HasSeen(first) {
		t.Error("first entry should still be in table")
	}

	// Add more entries to overwrite the oldest
	for i := range 5 {
		pkt := makePacket(codec.PayloadTypeGrpTxt, []byte{byte(i + 10)})
		d.HasSeen(pkt)
	}

	// The original first entry should now be evicted
	freshFirst := makePacket(codec.PayloadTypeTxtMsg, []byte{0x00})
	if d.HasSeen(freshFirst) {
		t.Error("evicted entry should not be marked as seen")
	}
}

func TestHasSeen_AckCircularOverwrite(t *testing.T) {
	d := NewWithCapacity(4, 2)

	ack1 := makeAckPacket(0xAAAAAAAA)
	ack2 := makeAckPacket(0xBBBBBBBB)
	ack3 := makeAckPacket(0xCCCCCCCC)

	d.HasSeen(ack1) // slot 0 = ack1
	d.HasSeen(ack2) // slot 1 = ack2
	d.HasSeen(ack3) // slot 0 = ack3, evicts ack1

	// ack3 should still be seen (in slot 0)
	if !d.HasSeen(ack3) {
		t.Error("ack3 should still be in table")
	}

	// ack2 should still be seen (in slot 1)
	if !d.HasSeen(ack2) {
		t.Error("ack2 should still be in table")
	}

	// ack1 was evicted — should not be seen
	if d.HasSeen(ack1) {
		t.Error("evicted ACK should not be marked as seen")
	}
}

func TestClear(t *testing.T) {
	d := New()
	pkt := makePacket(codec.PayloadTypeTxtMsg, []byte{0x01})
	ack := makeAckPacket(0x12345678)

	d.HasSeen(pkt)
	d.HasSeen(ack)

	d.Clear()

	if d.HasSeen(pkt) {
		t.Error("packet should not be seen after clear")
	}
	if d.HasSeen(ack) {
		t.Error("ACK should not be seen after clear")
	}
}

func TestCalculatePacketHash_TraceIncludesPathLen(t *testing.T) {
	pkt1 := &codec.Packet{
		Header:  (codec.PayloadTypeTrace << codec.PHTypeShift) | codec.RouteTypeFlood,
		PathLen: 3,
		Payload: []byte{0x01, 0x02, 0x03},
	}
	pkt2 := &codec.Packet{
		Header:  (codec.PayloadTypeTrace << codec.PHTypeShift) | codec.RouteTypeFlood,
		PathLen: 5,
		Payload: []byte{0x01, 0x02, 0x03},
	}

	hash1 := CalculatePacketHash(pkt1)
	hash2 := CalculatePacketHash(pkt2)

	if hash1 == hash2 {
		t.Error("TRACE packets with different path_len should have different hashes")
	}
}

func TestCalculatePacketHash_NonTraceIgnoresPathLen(t *testing.T) {
	pkt1 := &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift) | codec.RouteTypeFlood,
		PathLen: 3,
		Payload: []byte{0x01, 0x02, 0x03},
	}
	pkt2 := &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift) | codec.RouteTypeFlood,
		PathLen: 5,
		Payload: []byte{0x01, 0x02, 0x03},
	}

	hash1 := CalculatePacketHash(pkt1)
	hash2 := CalculatePacketHash(pkt2)

	if hash1 != hash2 {
		t.Error("non-TRACE packets with same payload should have same hash regardless of path_len")
	}
}
