package router

import (
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
)

func TestTransportKeyFromRegion(t *testing.T) {
	key := TransportKeyFromRegion("#test-region")
	if key.IsNull() {
		t.Error("derived key should not be null")
	}

	// Same input should produce same key
	key2 := TransportKeyFromRegion("#test-region")
	if key != key2 {
		t.Error("same region name should produce same key")
	}

	// Different input should produce different key
	key3 := TransportKeyFromRegion("#other-region")
	if key == key3 {
		t.Error("different region names should produce different keys")
	}
}

func TestCalcTransportCode(t *testing.T) {
	key := TransportKeyFromRegion("#test")
	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02, 0x03})

	code := key.CalcTransportCode(pkt)
	if code == 0 {
		t.Error("transport code should not be zero (reserved)")
	}

	// Deterministic: same key + packet = same code
	code2 := key.CalcTransportCode(pkt)
	if code != code2 {
		t.Errorf("transport code not deterministic: %d != %d", code, code2)
	}

	// Different payload = different code
	pkt2 := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x04, 0x05, 0x06})
	code3 := key.CalcTransportCode(pkt2)
	if code == code3 {
		t.Error("different payloads should produce different codes")
	}

	// Different payload type = different code
	pkt3 := makeFloodPacket(codec.PayloadTypeAdvert, []byte{0x01, 0x02, 0x03})
	code4 := key.CalcTransportCode(pkt3)
	if code == code4 {
		t.Error("different payload types should produce different codes")
	}
}

func TestTransportKey_IsNull(t *testing.T) {
	var key TransportKey
	if !key.IsNull() {
		t.Error("zero key should be null")
	}

	key[0] = 1
	if key.IsNull() {
		t.Error("non-zero key should not be null")
	}
}

func TestNewTransportCodeValidator_Match(t *testing.T) {
	key := TransportKeyFromRegion("#mesh-region")
	validator := NewTransportCodeValidator([]TransportKey{key})

	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift) | codec.RouteTypeTransportFlood,
		Payload: []byte{0x01, 0x02, 0x03},
	}
	pkt.TransportCodes[0] = key.CalcTransportCode(pkt)

	if !validator(pkt) {
		t.Error("validator should accept packet with matching transport code")
	}
}

func TestNewTransportCodeValidator_Mismatch(t *testing.T) {
	key := TransportKeyFromRegion("#mesh-region")
	validator := NewTransportCodeValidator([]TransportKey{key})

	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift) | codec.RouteTypeTransportFlood,
		Payload: []byte{0x01, 0x02, 0x03},
	}
	pkt.TransportCodes[0] = 0x1234 // wrong code

	if validator(pkt) {
		t.Error("validator should reject packet with wrong transport code")
	}
}

func TestNewTransportCodeValidator_MultipleKeys(t *testing.T) {
	key1 := TransportKeyFromRegion("#region-a")
	key2 := TransportKeyFromRegion("#region-b")
	validator := NewTransportCodeValidator([]TransportKey{key1, key2})

	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift) | codec.RouteTypeTransportFlood,
		Payload: []byte{0x01, 0x02, 0x03},
	}
	// Set code matching key2 but not key1
	pkt.TransportCodes[0] = key2.CalcTransportCode(pkt)

	if !validator(pkt) {
		t.Error("validator should accept packet matching any key in the set")
	}
}

func TestHandlePacket_TransportCodeDrop(t *testing.T) {
	mt := newMockTransport()
	key := TransportKeyFromRegion("#test")
	r := New(Config{
		SelfID:                selfID(0xAA),
		ForwardPackets:        true,
		ValidateTransportCode: NewTransportCodeValidator([]TransportKey{key}),
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	var appCalled bool
	r.SetPacketHandler(func(pkt *codec.Packet, src transport.PacketSource) {
		appCalled = true
	})

	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift) | codec.RouteTypeTransportFlood,
		Payload: []byte{0x01, 0x02, 0x03},
	}
	pkt.TransportCodes[0] = 0xBEEF // wrong code

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if appCalled {
		t.Error("app handler should not be called for rejected transport code")
	}
	if mt.sentCount() != 0 {
		t.Errorf("should not forward rejected packet, got %d", mt.sentCount())
	}
}

func TestHandlePacket_TransportCodeAccept(t *testing.T) {
	mt := newMockTransport()
	key := TransportKeyFromRegion("#test")
	r := New(Config{
		SelfID:                selfID(0xAA),
		ForwardPackets:        true,
		ValidateTransportCode: NewTransportCodeValidator([]TransportKey{key}),
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	var appCalled bool
	r.SetPacketHandler(func(pkt *codec.Packet, src transport.PacketSource) {
		appCalled = true
	})

	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift) | codec.RouteTypeTransportFlood,
		Payload: []byte{0x01, 0x02, 0x03},
	}
	pkt.TransportCodes[0] = key.CalcTransportCode(pkt)

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if !appCalled {
		t.Error("app handler should be called for accepted transport code")
	}
	if mt.sentCount() != 1 {
		t.Errorf("should forward accepted packet, got %d", mt.sentCount())
	}
}

func TestHandlePacket_NoTransportCodesPassThrough(t *testing.T) {
	mt := newMockTransport()
	key := TransportKeyFromRegion("#test")
	r := New(Config{
		SelfID:                selfID(0xAA),
		ForwardPackets:        true,
		ValidateTransportCode: NewTransportCodeValidator([]TransportKey{key}),
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	// Regular flood packet (no transport codes) should pass through
	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02, 0x03})
	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 1 {
		t.Errorf("regular packets should pass through even with validator set, got %d", mt.sentCount())
	}
}

func TestHandlePacket_NilValidatorPassesTransportCodes(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{
		SelfID:         selfID(0xAA),
		ForwardPackets: true,
		// ValidateTransportCode is nil
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift) | codec.RouteTypeTransportFlood,
		Payload: []byte{0x01, 0x02, 0x03},
	}
	pkt.TransportCodes[0] = 0x1234

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	if mt.sentCount() != 1 {
		t.Errorf("nil validator should pass all packets, got %d", mt.sentCount())
	}
}

func TestHandlePacket_TransportCodeNotConsumeDedup(t *testing.T) {
	mt := newMockTransport()
	key := TransportKeyFromRegion("#test")
	r := New(Config{
		SelfID:                selfID(0xAA),
		ForwardPackets:        true,
		ValidateTransportCode: NewTransportCodeValidator([]TransportKey{key}),
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift) | codec.RouteTypeTransportFlood,
		Payload: []byte{0x01, 0x02, 0x03},
	}
	pkt.TransportCodes[0] = 0xBEEF // wrong code — rejected

	r.HandlePacket(pkt, transport.PacketSourceSerial)

	// Now send the same payload with correct code — should NOT be deduped
	pkt2 := &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift) | codec.RouteTypeTransportFlood,
		Payload: []byte{0x01, 0x02, 0x03},
	}
	pkt2.TransportCodes[0] = key.CalcTransportCode(pkt2)

	r.HandlePacket(pkt2, transport.PacketSourceSerial)

	if mt.sentCount() != 1 {
		t.Errorf("rejected packet should not consume dedup slot, got %d sends", mt.sentCount())
	}
}
