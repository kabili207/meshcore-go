package mqtt

import (
	"bytes"
	"context"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
)

func TestNew_Defaults(t *testing.T) {
	tr := New(Config{
		Broker: "tcp://localhost:1883",
		NodeID: "test",
	})

	if tr.cfg.Framing != FramingBridge {
		t.Errorf("expected default framing FramingBridge, got %v", tr.cfg.Framing)
	}
	if tr.cfg.Topic != "meshcore/bridge/packets" {
		t.Errorf("expected default topic %q, got %q", "meshcore/bridge/packets", tr.cfg.Topic)
	}
	if tr.log == nil {
		t.Error("expected logger to be set")
	}
}

func TestNew_CustomConfig(t *testing.T) {
	tr := New(Config{
		Broker:   "tcp://broker.example.com:1883",
		Username: "user",
		Password: "pass",
		Topic:    "custom/topic",
		NodeID:   "my-node",
	})

	if tr.cfg.Topic != "custom/topic" {
		t.Errorf("expected topic %q, got %q", "custom/topic", tr.cfg.Topic)
	}
	if tr.cfg.NodeID != "my-node" {
		t.Errorf("expected node ID %q, got %q", "my-node", tr.cfg.NodeID)
	}
}

func TestStart_MissingBroker(t *testing.T) {
	tr := New(Config{NodeID: "test"})
	err := tr.Start(context.Background())
	if err == nil {
		t.Fatal("expected error with empty broker")
	}
}

func TestStart_MissingNodeID(t *testing.T) {
	tr := New(Config{Broker: "tcp://localhost:1883"})
	err := tr.Start(context.Background())
	if err == nil {
		t.Fatal("expected error with empty node ID")
	}
}

func TestSendPacket_NotConnected(t *testing.T) {
	tr := New(Config{
		Broker: "tcp://localhost:1883",
		NodeID: "test",
	})

	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeAdvert << codec.PHTypeShift) | codec.RouteTypeFlood,
		Payload: []byte{0x01, 0x02},
	}

	err := tr.SendPacket(pkt)
	if err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestIsConnected_Default(t *testing.T) {
	tr := New(Config{
		Broker: "tcp://localhost:1883",
		NodeID: "test",
	})

	if tr.IsConnected() {
		t.Error("expected not connected initially")
	}
}

func TestNew_RawFramingDefaultTopic(t *testing.T) {
	tr := New(Config{
		Broker:  "tcp://localhost:1883",
		NodeID:  "test",
		Framing: FramingRaw,
	})

	if tr.cfg.Topic != "meshcore/bridge" {
		t.Errorf("expected default topic %q, got %q", "meshcore/bridge", tr.cfg.Topic)
	}
}

type fakeMessage struct{ payload []byte }

func (m fakeMessage) Duplicate() bool   { return false }
func (m fakeMessage) Qos() byte         { return 0 }
func (m fakeMessage) Retained() bool    { return false }
func (m fakeMessage) Topic() string     { return "" }
func (m fakeMessage) MessageID() uint16 { return 0 }
func (m fakeMessage) Payload() []byte   { return m.payload }
func (m fakeMessage) Ack()              {}

func TestHandleMessage_Framing(t *testing.T) {
	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeAdvert << codec.PHTypeShift) | codec.RouteTypeFlood,
		Payload: []byte{0x01, 0x02},
	}
	raw := pkt.WriteTo()
	framed, err := codec.EncodeBridgeFrame(raw, "secret")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	wrongSecret, _ := codec.EncodeBridgeFrame(raw, "other")

	tests := []struct {
		name    string
		framing Framing
		payload []byte
		want    bool
	}{
		{"raw accepts raw", FramingRaw, raw, true},
		{"bridge accepts framed", FramingBridge, framed, true},
		{"bridge drops raw", FramingBridge, raw, false},
		{"bridge drops wrong secret", FramingBridge, wrongSecret, false},
		{"raw drops framed", FramingRaw, framed, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := New(Config{NodeID: "test", Framing: tt.framing, Secret: "secret"})
			var got *codec.Packet
			tr.SetPacketHandler(func(p *codec.Packet, _ transport.PacketSource) { got = p })

			tr.handleMessage(nil, fakeMessage{tt.payload})

			if (got != nil) != tt.want {
				t.Fatalf("delivered = %v, want %v", got != nil, tt.want)
			}
			if got != nil && !bytes.Equal(got.Payload, pkt.Payload) {
				t.Errorf("payload = % x, want % x", got.Payload, pkt.Payload)
			}
		})
	}
}
