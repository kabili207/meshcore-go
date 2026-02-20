package router

import (
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
)

// traceID returns a MeshCoreID whose first N bytes match the given hash bytes.
// This supports variable-size TRACE hash matching.
func traceID(hashBytes ...byte) core.MeshCoreID {
	var id core.MeshCoreID
	copy(id[:], hashBytes)
	return id
}

func makeTracePacket(pathHashes []byte, flags uint8, pathLen uint8, path []byte, snr int8) *codec.Packet {
	payload := codec.BuildTracePayload(0x12345678, 0xAABBCCDD, flags, pathHashes)
	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeTrace << codec.PHTypeShift) | codec.RouteTypeDirect,
		PathLen: pathLen,
		Path:    make([]byte, codec.MaxPathSize),
		Payload: payload,
		SNR:     snr,
	}
	copy(pkt.Path, path)
	return pkt
}

func TestHandleTrace_SingleHopForward(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         traceID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	// 1-byte hashes: [0xAA, 0xBB, 0xCC] — we're hop 0
	pkt := makeTracePacket(
		[]byte{0xAA, 0xBB, 0xCC}, // pathHashes
		0x00,                      // flags: 1-byte hashes
		0,                         // pathLen: no hops yet
		nil,                       // path: empty
		40,                        // SNR: 10.0 dB raw
	)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 1 {
		t.Fatalf("expected 1 packet sent, got %d", mt.sentCount())
	}

	sent := mt.lastSent()
	if sent.PathLen != 1 {
		t.Errorf("forwarded pathLen = %d, want 1", sent.PathLen)
	}
	if sent.Path[0] != byte(40) {
		t.Errorf("forwarded path[0] (SNR) = %d, want 40", sent.Path[0])
	}
}

func TestHandleTrace_MultiHop(t *testing.T) {
	mt := newMockTransport()
	// We are the second hop (index 1) with 1-byte hash 0xBB
	r := New(Config{
		SelfID:         traceID(0xBB),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	// 1-byte hashes: [0xAA, 0xBB, 0xCC]
	// pathLen=1 means hop 0 already done, SNR from hop 0 stored in path[0]
	pkt := makeTracePacket(
		[]byte{0xAA, 0xBB, 0xCC},
		0x00,
		1,
		[]byte{20}, // hop 0's SNR
		-8,         // our SNR
	)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 1 {
		t.Fatalf("expected 1 packet sent, got %d", mt.sentCount())
	}

	sent := mt.lastSent()
	if sent.PathLen != 2 {
		t.Errorf("forwarded pathLen = %d, want 2", sent.PathLen)
	}
	if sent.Path[0] != 20 {
		t.Errorf("path[0] = %d, want 20 (hop 0 SNR preserved)", sent.Path[0])
	}
	snrVal := int8(-8)
	if sent.Path[1] != byte(snrVal) {
		t.Errorf("path[1] = %02x, want %02x (our SNR)", sent.Path[1], byte(snrVal))
	}
}

func TestHandleTrace_Complete(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         traceID(0xCC),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	var appCalled bool
	r.SetPacketHandler(func(pkt *codec.Packet, src transport.PacketSource) {
		appCalled = true
	})

	// 1-byte hashes: [0xAA, 0xBB] — only 2 hops
	// pathLen=2 means both hops done → offset(2) >= len(pathHashes)(2) → complete
	pkt := makeTracePacket(
		[]byte{0xAA, 0xBB},
		0x00,
		2,
		[]byte{20, 30}, // SNR values from hop 0, hop 1
		0,
	)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if !appCalled {
		t.Error("expected app handler to be called when trace is complete")
	}
	if mt.sentCount() != 0 {
		t.Errorf("completed trace should not be forwarded, got %d sends", mt.sentCount())
	}
}

func TestHandleTrace_WrongHash(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         traceID(0xFF), // doesn't match any hash in the path
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	var appCalled bool
	r.SetPacketHandler(func(pkt *codec.Packet, src transport.PacketSource) {
		appCalled = true
	})

	pkt := makeTracePacket(
		[]byte{0xAA, 0xBB, 0xCC},
		0x00,
		0,
		nil,
		0,
	)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if appCalled {
		t.Error("app should not be called when hash doesn't match")
	}
	if mt.sentCount() != 0 {
		t.Errorf("should not forward when hash doesn't match, got %d sends", mt.sentCount())
	}
}

func TestHandleTrace_ForwardingDisabled(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         traceID(0xAA),
		ForwardPackets: false, // disabled
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	pkt := makeTracePacket(
		[]byte{0xAA, 0xBB},
		0x00,
		0,
		nil,
		0,
	)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 0 {
		t.Errorf("should not forward when ForwardPackets=false, got %d sends", mt.sentCount())
	}
}

func TestHandleTrace_TwoByteHashes(t *testing.T) {
	mt := newMockTransport()
	// 2-byte hash match: first 2 bytes of pubkey must be 0xAA, 0xBB
	r := New(Config{
		SelfID:         traceID(0xAA, 0xBB),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	// flags=0x01 → 2-byte hashes; pathHashes = [0xAA,0xBB, 0xCC,0xDD]
	pkt := makeTracePacket(
		[]byte{0xAA, 0xBB, 0xCC, 0xDD},
		0x01, // 2-byte hashes
		0,
		nil,
		16,
	)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 1 {
		t.Fatalf("expected 1 packet sent, got %d", mt.sentCount())
	}

	sent := mt.lastSent()
	if sent.PathLen != 1 {
		t.Errorf("forwarded pathLen = %d, want 1", sent.PathLen)
	}
}

func TestHandleTrace_FourByteHashes(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         traceID(0x01, 0x02, 0x03, 0x04),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	// flags=0x02 → 4-byte hashes; pathHashes = [01,02,03,04, 05,06,07,08]
	pkt := makeTracePacket(
		[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		0x02, // 4-byte hashes
		0,
		nil,
		-20,
	)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 1 {
		t.Fatalf("expected 1 packet sent, got %d", mt.sentCount())
	}
}

func TestHandleTrace_Dedup(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         traceID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	pkt := makeTracePacket(
		[]byte{0xAA, 0xBB},
		0x00,
		0,
		nil,
		10,
	)

	r.HandlePacket(pkt, transport.PacketSourceSerial)
	r.HandlePacket(pkt, transport.PacketSourceSerial) // duplicate

	// First one gets forwarded, second is deduped at Gate 3
	if mt.sentCount() != 1 {
		t.Errorf("expected 1 send (dedup should suppress second), got %d", mt.sentCount())
	}
}

func TestHandleTrace_MaxPathSize(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         traceID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	// PathLen already at MaxPathSize → should be dropped
	pkt := makeTracePacket(
		[]byte{0xAA, 0xBB},
		0x00,
		codec.MaxPathSize, // at limit
		nil,
		0,
	)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 0 {
		t.Errorf("should drop trace at max path size, got %d sends", mt.sentCount())
	}
}

func TestHandleTrace_ExcludesSource(t *testing.T) {
	mqtt := newMockTransport()
	serial := newMockTransport()
	r := New(Config{
		SelfID:         traceID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mqtt, transport.PacketSourceMQTT)
	r.AddTransport(serial, transport.PacketSourceSerial)

	pkt := makeTracePacket(
		[]byte{0xAA, 0xBB},
		0x00,
		0,
		nil,
		10,
	)

	// Arrives from serial — should forward to MQTT, not back to serial
	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mqtt.sentCount() != 1 {
		t.Errorf("MQTT should receive forwarded trace, got %d", mqtt.sentCount())
	}
	if serial.sentCount() != 0 {
		t.Errorf("serial should NOT receive echo, got %d", serial.sentCount())
	}
}
