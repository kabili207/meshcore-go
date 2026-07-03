package router

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
)

// mockTransport implements transport.Transport for testing.
type mockTransport struct {
	mu        sync.Mutex
	connected bool
	sent      []*codec.Packet
	handler   transport.PacketHandler
}

func newMockTransport() *mockTransport {
	return &mockTransport{connected: true}
}

func (m *mockTransport) Start(_ context.Context) error { return nil }
func (m *mockTransport) Stop() error                   { return nil }

func (m *mockTransport) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connected
}

func (m *mockTransport) SetPacketHandler(fn transport.PacketHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handler = fn
}

func (m *mockTransport) SetStateHandler(_ transport.StateHandler) {}

func (m *mockTransport) SendPacket(pkt *codec.Packet) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, pkt)
	return nil
}

func (m *mockTransport) sentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func (m *mockTransport) lastSent() *codec.Packet {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		return nil
	}
	return m.sent[len(m.sent)-1]
}

// selfID returns a MeshCoreID whose first byte (hash) is the given value.
func selfID(hash byte) core.MeshCoreID {
	var id core.MeshCoreID
	id[0] = hash
	return id
}

func makeFloodPacket(payloadType uint8, payload []byte) *codec.Packet {
	return &codec.Packet{
		Header:  (payloadType << codec.PHTypeShift) | codec.RouteTypeFlood,
		Payload: payload,
	}
}

func makeDirectPacket(payloadType uint8, path []byte, payload []byte) *codec.Packet {
	return &codec.Packet{
		Header:  (payloadType << codec.PHTypeShift) | codec.RouteTypeDirect,
		PathLen: uint8(len(path)),
		Path:    append([]byte{}, path...),
		Payload: payload,
	}
}

// --- Flood Routing Tests ---

func TestSendFloodScoped_NoScope(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{SelfID: selfID(0xAA)})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02, 0x03})
	r.SendFloodScoped(pkt)

	sent := mt.lastSent()
	if sent == nil {
		t.Fatal("expected a packet to be sent")
	}
	// With no scope set, a scoped send must be an ordinary unscoped flood.
	if sent.RouteType() != codec.RouteTypeFlood {
		t.Errorf("route type = %d, want RouteTypeFlood", sent.RouteType())
	}
	if sent.HasTransportCodes() {
		t.Error("unscoped send must not carry transport codes")
	}
}

func TestSendFloodScoped_WithScope(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{SelfID: selfID(0xAA)})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	key := TransportKeyFromRegion("#us")
	r.SetSendScope(key)

	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02, 0x03})
	r.SendFloodScoped(pkt)

	sent := mt.lastSent()
	if sent == nil {
		t.Fatal("expected a packet to be sent")
	}
	if sent.RouteType() != codec.RouteTypeTransportFlood {
		t.Fatalf("route type = %d, want RouteTypeTransportFlood", sent.RouteType())
	}
	// The attached code must be the scope's code for this packet, so a repeater
	// configured with the same region key accepts it.
	if got := sent.TransportCodes[0]; got != key.CalcTransportCode(sent) {
		t.Errorf("transport_codes[0] = %d, want %d", got, key.CalcTransportCode(sent))
	}
	if sent.TransportCodes[1] != 0 {
		t.Errorf("transport_codes[1] = %d, want 0", sent.TransportCodes[1])
	}
	if !NewTransportCodeValidator([]TransportKey{key})(sent) {
		t.Error("a validator with the same region key should accept the scoped packet")
	}

	// Clearing the scope reverts to unscoped sending.
	r.ClearSendScope()
	pkt2 := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x04, 0x05})
	r.SendFloodScoped(pkt2)
	if mt.lastSent().HasTransportCodes() {
		t.Error("after ClearSendScope, send must be unscoped")
	}
}

func TestHandlePacket_FloodForward(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02, 0x03})

	r.HandlePacket(pkt, transport.PacketSourceSerial) // different source so not excluded

	if mt.sentCount() != 1 {
		t.Fatalf("expected 1 packet sent, got %d", mt.sentCount())
	}

	sent := mt.lastSent()
	if sent.PathLen != 1 {
		t.Errorf("forwarded packet path_len = %d, want 1", sent.PathLen)
	}
	if sent.Path[0] != 0xAA {
		t.Errorf("forwarded packet path[0] = %02x, want 0xAA", sent.Path[0])
	}
}

func TestHandlePacket_FloodNoForward(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: false, // forwarding disabled
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	var appCalled bool
	r.SetPacketHandler(func(pkt *codec.Packet, src transport.PacketSource) {
		appCalled = true
	})

	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02, 0x03})
	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if !appCalled {
		t.Error("app handler should be called even when forwarding is disabled")
	}
	if mt.sentCount() != 0 {
		t.Errorf("no packets should be forwarded, got %d", mt.sentCount())
	}
}

func TestHandlePacket_FloodMaxPath(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
		MaxFloodHops:   4,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	// Packet already has 4 hops in path — at the limit
	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01})
	pkt.PathLen = 4
	pkt.Path = []byte{0x01, 0x02, 0x03, 0x04}

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 0 {
		t.Errorf("should not forward packet at max hops, got %d sends", mt.sentCount())
	}
}

func TestHandlePacket_FloodAdvertCap(t *testing.T) {
	// Default MaxAdvertFloodHops is 8: an advert at 7 hops forwards, at 8 it drops,
	// while non-advert flood traffic at the same hop count is unaffected.
	newRouter := func() (*Router, *mockTransport) {
		mt := newMockTransport()
		r := New(Config{SelfID: selfID(0xAA), ForwardPackets: true})
		r.AddTransport(mt, transport.PacketSourceMQTT)
		return r, mt
	}

	advert7 := makeFloodPacket(codec.PayloadTypeAdvert, []byte{0x01})
	advert7.PathLen = 7
	advert7.Path = []byte{1, 2, 3, 4, 5, 6, 7}
	r, mt := newRouter()
	r.HandlePacket(advert7, transport.PacketSourceSerial)
	if mt.sentCount() != 1 {
		t.Errorf("advert at 7 hops should forward, got %d sends", mt.sentCount())
	}

	advert8 := makeFloodPacket(codec.PayloadTypeAdvert, []byte{0x01})
	advert8.PathLen = 8
	advert8.Path = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	r, mt = newRouter()
	r.HandlePacket(advert8, transport.PacketSourceSerial)
	if mt.sentCount() != 0 {
		t.Errorf("advert at 8 hops should drop, got %d sends", mt.sentCount())
	}

	// A non-advert flood packet at 8 hops is well under MaxFloodHops and forwards.
	txt8 := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01})
	txt8.PathLen = 8
	txt8.Path = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	r, mt = newRouter()
	r.HandlePacket(txt8, transport.PacketSourceSerial)
	if mt.sentCount() != 1 {
		t.Errorf("non-advert flood at 8 hops should forward, got %d sends", mt.sentCount())
	}
}

func TestHandlePacket_FloodUnscopedCap(t *testing.T) {
	// With MaxUnscopedFloodHops=4 but MaxFloodHops at its default 64, an unscoped
	// flood packet at 4 hops is dropped by the unscoped cap specifically.
	mt := newMockTransport()
	r := New(Config{
		SelfID:               selfID(0xAA),
		ForwardPackets:       true,
		MaxUnscopedFloodHops: 4,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01})
	pkt.PathLen = 4
	pkt.Path = []byte{1, 2, 3, 4}
	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 0 {
		t.Errorf("unscoped flood at 4 hops should drop, got %d sends", mt.sentCount())
	}
}

func TestHandlePacket_FloodDoNotRetransmit(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	var appCalled bool
	r.SetPacketHandler(func(pkt *codec.Packet, src transport.PacketSource) {
		appCalled = true
	})

	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02})
	pkt.MarkDoNotRetransmit()

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	// DoNotRetransmit packets have header=0xFF which makes PayloadType/RouteType
	// return garbage. The dedup check still works but the route type gates will
	// not match flood or direct. The packet should be dropped without dispatch.
	if appCalled {
		t.Error("app handler should not be called for DoNotRetransmit packets " +
			"(they don't match any route type gate)")
	}
	if mt.sentCount() != 0 {
		t.Errorf("should not forward DoNotRetransmit packet, got %d sends", mt.sentCount())
	}
}

func TestHandlePacket_FloodAppSuppressesForward(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	// App callback marks the packet as "consumed" — suppress forwarding
	r.SetPacketHandler(func(pkt *codec.Packet, src transport.PacketSource) {
		pkt.MarkDoNotRetransmit()
	})

	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02, 0x03})
	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 0 {
		t.Errorf("app suppressed forwarding, but %d packets sent", mt.sentCount())
	}
}

// --- Direct Routing Tests ---

func TestHandlePacket_DirectForward(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	// path = [0xAA, 0xBB, 0xCC] — we're the first hop
	pkt := makeDirectPacket(codec.PayloadTypeTxtMsg,
		[]byte{0xAA, 0xBB, 0xCC},
		[]byte{0x01, 0x02})

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 1 {
		t.Fatalf("expected 1 packet forwarded, got %d", mt.sentCount())
	}

	sent := mt.lastSent()
	if sent.PathLen != 2 {
		t.Errorf("forwarded path_len = %d, want 2", sent.PathLen)
	}
	if sent.Path[0] != 0xBB {
		t.Errorf("forwarded path[0] = %02x, want 0xBB", sent.Path[0])
	}
	if sent.Path[1] != 0xCC {
		t.Errorf("forwarded path[1] = %02x, want 0xCC", sent.Path[1])
	}
}

func TestHandlePacket_DirectMiss(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	// path[0] = 0xBB, not our hash
	pkt := makeDirectPacket(codec.PayloadTypeTxtMsg,
		[]byte{0xBB, 0xCC},
		[]byte{0x01})

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 0 {
		t.Errorf("should not forward when path[0] doesn't match, got %d", mt.sentCount())
	}
}

func TestHandlePacket_DirectNoForwardingDisabled(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: false, // disabled
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	pkt := makeDirectPacket(codec.PayloadTypeTxtMsg,
		[]byte{0xAA, 0xBB},
		[]byte{0x01})

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 0 {
		t.Errorf("should not forward when ForwardPackets=false, got %d", mt.sentCount())
	}
}

func TestHandlePacket_DirectZeroHop(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	var appCalled bool
	r.SetPacketHandler(func(pkt *codec.Packet, src transport.PacketSource) {
		appCalled = true
	})

	// Zero-hop: direct with empty path
	pkt := makeDirectPacket(codec.PayloadTypeTxtMsg, nil, []byte{0x01, 0x02})

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if !appCalled {
		t.Error("app handler should be called for zero-hop direct packets")
	}
	if mt.sentCount() != 0 {
		t.Errorf("zero-hop packets should not be forwarded, got %d", mt.sentCount())
	}
}

// --- Deduplication Tests ---

func TestHandlePacket_Dedup(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	callCount := 0
	r.SetPacketHandler(func(pkt *codec.Packet, src transport.PacketSource) {
		callCount++
	})

	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02, 0x03})

	r.HandlePacket(pkt, transport.PacketSourceSerial)
	r.HandlePacket(pkt, transport.PacketSourceSerial) // duplicate

	if callCount != 1 {
		t.Errorf("app handler called %d times, want 1 (dedup should suppress)", callCount)
	}
	if mt.sentCount() != 1 {
		t.Errorf("expected 1 forward (not 2), got %d", mt.sentCount())
	}
}

// --- Version Gate ---

func TestHandlePacket_UnsupportedVersion(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01})
	// Set version to 2 (unsupported)
	pkt.Header |= (0x02 << codec.PHVerShift)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 0 {
		t.Errorf("should drop unsupported version, got %d sends", mt.sentCount())
	}
}

// --- Multiple Transports ---

func TestHandlePacket_MultipleTransports(t *testing.T) {
	mqtt := newMockTransport()
	serial := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mqtt, transport.PacketSourceMQTT)
	r.AddTransport(serial, transport.PacketSourceSerial)

	// Packet arrives from serial — should forward to MQTT but not back to serial
	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02, 0x03})
	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mqtt.sentCount() != 1 {
		t.Errorf("MQTT should receive forwarded packet, got %d", mqtt.sentCount())
	}
	if serial.sentCount() != 0 {
		t.Errorf("serial should NOT receive echo, got %d", serial.sentCount())
	}
}

func TestHandlePacket_DisconnectedTransportSkipped(t *testing.T) {
	connected := newMockTransport()
	disconnected := newMockTransport()
	disconnected.connected = false

	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(connected, transport.PacketSourceMQTT)
	r.AddTransport(disconnected, transport.PacketSourceSerial)

	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02})
	r.HandlePacket(pkt, 99) // source that doesn't match either transport

	if connected.sentCount() != 1 {
		t.Errorf("connected transport should get packet, got %d", connected.sentCount())
	}
	if disconnected.sentCount() != 0 {
		t.Errorf("disconnected transport should be skipped, got %d", disconnected.sentCount())
	}
}

// --- Send Functions ---

func TestSendFlood(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{SelfID: selfID(0xAA)})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift),
		Payload: []byte{0x01, 0x02},
	}
	r.SendFlood(pkt)

	if mt.sentCount() != 1 {
		t.Fatalf("expected 1 send, got %d", mt.sentCount())
	}
	if pkt.RouteType() != codec.RouteTypeFlood {
		t.Errorf("route type = %d, want flood(%d)", pkt.RouteType(), codec.RouteTypeFlood)
	}
	if pkt.PathLen != 0 {
		t.Errorf("path_len = %d, want 0", pkt.PathLen)
	}

	// Sending the same packet again should still send (SendFlood doesn't dedup outbound).
	// But if it loops back via HandlePacket, dedup should catch it.
	r.HandlePacket(pkt, transport.PacketSourceMQTT)
	if mt.sentCount() != 1 {
		t.Errorf("loopback should be deduped, got %d total sends", mt.sentCount())
	}
}

func TestSendDirect(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{SelfID: selfID(0xAA)})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift),
		Payload: []byte{0x01, 0x02},
	}
	path := []byte{0xBB, 0xCC}
	r.SendDirect(pkt, path)

	if mt.sentCount() != 1 {
		t.Fatalf("expected 1 send, got %d", mt.sentCount())
	}
	if pkt.RouteType() != codec.RouteTypeDirect {
		t.Errorf("route type = %d, want direct(%d)", pkt.RouteType(), codec.RouteTypeDirect)
	}
	if pkt.PathLen != 2 {
		t.Errorf("path_len = %d, want 2", pkt.PathLen)
	}
	if pkt.Path[0] != 0xBB || pkt.Path[1] != 0xCC {
		t.Errorf("path = %v, want [BB CC]", pkt.Path)
	}
}

func TestSendZeroHop(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{SelfID: selfID(0xAA)})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeControl << codec.PHTypeShift),
		Payload: []byte{0x01},
	}
	r.SendZeroHop(pkt)

	if mt.sentCount() != 1 {
		t.Fatalf("expected 1 send, got %d", mt.sentCount())
	}
	if pkt.RouteType() != codec.RouteTypeDirect {
		t.Errorf("route type = %d, want direct(%d)", pkt.RouteType(), codec.RouteTypeDirect)
	}
	if pkt.PathLen != 0 {
		t.Errorf("path_len = %d, want 0", pkt.PathLen)
	}
}

// --- removeSelfFromPath ---

func TestRemoveSelfFromPath(t *testing.T) {
	pkt := &codec.Packet{
		PathLen: 3,
		Path:    []byte{0xAA, 0xBB, 0xCC},
	}

	removeSelfFromPath(pkt)

	if pkt.PathLen != 2 {
		t.Errorf("path_len = %d, want 2", pkt.PathLen)
	}
	if pkt.Path[0] != 0xBB {
		t.Errorf("path[0] = %02x, want 0xBB", pkt.Path[0])
	}
	if pkt.Path[1] != 0xCC {
		t.Errorf("path[1] = %02x, want 0xCC", pkt.Path[1])
	}
}

func TestRemoveSelfFromPath_SingleHop(t *testing.T) {
	pkt := &codec.Packet{
		PathLen: 1,
		Path:    []byte{0xAA},
	}

	removeSelfFromPath(pkt)

	if pkt.PathLen != 0 {
		t.Errorf("path_len = %d, want 0", pkt.PathLen)
	}
}

func TestRemoveSelfFromPath_EmptyPath(t *testing.T) {
	pkt := &codec.Packet{PathLen: 0}
	removeSelfFromPath(pkt) // should not panic
	if pkt.PathLen != 0 {
		t.Errorf("path_len = %d, want 0", pkt.PathLen)
	}
}

// --- Multipart Tests ---

func TestHandlePacket_Multipart(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: false, // don't forward, just dispatch to app
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	var dispatched []*codec.Packet
	r.SetPacketHandler(func(pkt *codec.Packet, src transport.PacketSource) {
		dispatched = append(dispatched, pkt)
	})

	// A multipart ACK is self-contained: it carries a complete ACK. `remaining`
	// only says how many more identical copies the sender will emit; the copies
	// are not fragments to concatenate.
	ack := []byte{0x12, 0x34, 0x56, 0x78}
	mp := func(remaining uint8) *codec.Packet {
		return &codec.Packet{
			Header:  (codec.PayloadTypeMultipart << codec.PHTypeShift) | codec.RouteTypeFlood,
			Payload: codec.BuildMultipartPayload(remaining, codec.PayloadTypeAck, ack),
		}
	}

	// The first copy dispatches the inner ACK immediately (no waiting).
	r.HandlePacket(mp(1), transport.PacketSourceMQTT)
	if len(dispatched) != 1 {
		t.Fatalf("expected 1 dispatch from a self-contained multipart ACK, got %d", len(dispatched))
	}
	if pt := dispatched[0].PayloadType(); pt != codec.PayloadTypeAck {
		t.Errorf("inner payload type = %d, want ACK (%d)", pt, codec.PayloadTypeAck)
	}
	if !bytes.Equal(dispatched[0].Payload, ack) {
		t.Errorf("inner payload = %x, want %x", dispatched[0].Payload, ack)
	}

	// A redundant copy of the same ACK is deduplicated, not dispatched again.
	r.HandlePacket(mp(0), transport.PacketSourceMQTT)
	if len(dispatched) != 1 {
		t.Errorf("redundant multipart ACK should be deduped; got %d dispatches", len(dispatched))
	}
}

// --- ACK Forwarding Tests ---

func TestHandlePacket_DirectAckForward(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	var appCalled bool
	r.SetPacketHandler(func(pkt *codec.Packet, src transport.PacketSource) {
		appCalled = true
	})

	// ACK with path [0xAA, 0xBB] — we're the first hop
	ackPayload := codec.BuildAckPayload(0xDEADBEEF)
	pkt := makeDirectPacket(codec.PayloadTypeAck, []byte{0xAA, 0xBB}, ackPayload)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	// App should be called first (early ACK receive)
	if !appCalled {
		t.Error("app handler should be called for ACK (early receive)")
	}

	// A new ACK packet should be sent
	if mt.sentCount() != 1 {
		t.Fatalf("expected 1 ACK forwarded, got %d", mt.sentCount())
	}

	sent := mt.lastSent()
	if sent.PayloadType() != codec.PayloadTypeAck {
		t.Errorf("forwarded type = %d, want ACK(%d)", sent.PayloadType(), codec.PayloadTypeAck)
	}
	if sent.PathLen != 1 {
		t.Errorf("forwarded pathLen = %d, want 1", sent.PathLen)
	}
	if sent.Path[0] != 0xBB {
		t.Errorf("forwarded path[0] = %02x, want 0xBB", sent.Path[0])
	}
}

func TestHandlePacket_DirectAckPreservesChecksum(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	checksum := uint32(0xCAFEBABE)
	ackPayload := codec.BuildAckPayload(checksum)
	pkt := makeDirectPacket(codec.PayloadTypeAck, []byte{0xAA, 0xBB}, ackPayload)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 1 {
		t.Fatalf("expected 1 packet sent, got %d", mt.sentCount())
	}

	sent := mt.lastSent()
	ack, err := codec.ParseAckPayload(sent.Payload)
	if err != nil {
		t.Fatalf("ParseAckPayload() error = %v", err)
	}
	if ack.Checksum != checksum {
		t.Errorf("checksum = %08x, want %08x", ack.Checksum, checksum)
	}
}

func TestHandlePacket_DirectAckFinalHop(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	var appCalled bool
	r.SetPacketHandler(func(pkt *codec.Packet, src transport.PacketSource) {
		appCalled = true
	})

	// ACK with path [0xAA] — we're the last relay hop
	ackPayload := codec.BuildAckPayload(0x12345678)
	pkt := makeDirectPacket(codec.PayloadTypeAck, []byte{0xAA}, ackPayload)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if !appCalled {
		t.Error("app handler should be called for ACK (early receive)")
	}

	// Should still forward (with pathLen=0, the next receiver is the destination)
	if mt.sentCount() != 1 {
		t.Fatalf("expected 1 ACK forwarded, got %d", mt.sentCount())
	}

	sent := mt.lastSent()
	if sent.PathLen != 0 {
		t.Errorf("forwarded pathLen = %d, want 0", sent.PathLen)
	}
}

func TestHandlePacket_DirectAckNotOurHop(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	// ACK with path[0] = 0xBB — not our hash
	ackPayload := codec.BuildAckPayload(0x12345678)
	pkt := makeDirectPacket(codec.PayloadTypeAck, []byte{0xBB, 0xCC}, ackPayload)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 0 {
		t.Errorf("should not forward when path[0] doesn't match, got %d", mt.sentCount())
	}
}

func TestHandlePacket_DirectAckSendToAll(t *testing.T) {
	mqtt := newMockTransport()
	serial := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mqtt, transport.PacketSourceMQTT)
	r.AddTransport(serial, transport.PacketSourceSerial)

	// ACK arrives from serial — forwarded ACK should go to ALL transports
	// (ACK forwarding uses sendToAll: true)
	ackPayload := codec.BuildAckPayload(0xDEADBEEF)
	pkt := makeDirectPacket(codec.PayloadTypeAck, []byte{0xAA, 0xBB}, ackPayload)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mqtt.sentCount() != 1 {
		t.Errorf("MQTT should receive forwarded ACK, got %d", mqtt.sentCount())
	}
	if serial.sentCount() != 1 {
		t.Errorf("serial should also receive forwarded ACK (sendToAll), got %d", serial.sentCount())
	}
}

func TestHandlePacket_DirectAckPreservesTransportCodes(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	ackPayload := codec.BuildAckPayload(0xDEADBEEF)
	pkt := &codec.Packet{
		Header:         (codec.PayloadTypeAck << codec.PHTypeShift) | codec.RouteTypeTransportDirect,
		TransportCodes: [2]uint16{0x1234, 0x5678},
		PathLen:        2,
		Path:           []byte{0xAA, 0xBB},
		Payload:        ackPayload,
	}

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 1 {
		t.Fatalf("expected 1 packet sent, got %d", mt.sentCount())
	}

	sent := mt.lastSent()
	if !sent.HasTransportCodes() {
		t.Error("forwarded ACK should preserve transport codes")
	}
	if sent.TransportCodes[0] != 0x1234 {
		t.Errorf("transport code[0] = %04x, want 0x1234", sent.TransportCodes[0])
	}
}

// --- Queue Drain Tests ---

func TestRouter_StartStop(t *testing.T) {
	r := New(Config{SelfID: selfID(0xAA)})
	ctx := context.Background()

	r.Start(ctx)
	if !r.started {
		t.Error("router should be started after Start()")
	}

	r.Stop()
	if r.started {
		t.Error("router should not be started after Stop()")
	}
}

func TestRouter_StopWithoutStart(t *testing.T) {
	r := New(Config{SelfID: selfID(0xAA)})
	// Stop without Start should not panic
	r.Stop()
}

// --- AddTransport auto-registration ---

func TestAddTransport_SetsHandler(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{SelfID: selfID(0xAA)})

	var appCalled bool
	r.SetPacketHandler(func(pkt *codec.Packet, src transport.PacketSource) {
		appCalled = true
	})

	r.AddTransport(mt, transport.PacketSourceMQTT)

	// Simulate the transport receiving a packet — it should invoke the
	// router's HandlePacket via the installed handler.
	mt.mu.Lock()
	handler := mt.handler
	mt.mu.Unlock()

	if handler == nil {
		t.Fatal("transport should have a packet handler installed")
	}

	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02})
	handler(pkt, transport.PacketSourceMQTT)

	if !appCalled {
		t.Error("app handler should be called when transport delivers a packet")
	}
}
