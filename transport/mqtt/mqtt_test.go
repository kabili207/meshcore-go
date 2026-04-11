package mqtt

import (
	"context"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
)

func TestNew_Defaults(t *testing.T) {
	tr := New(Config{
		Broker: "tcp://localhost:1883",
		NodeID: "test",
	})

	if tr.cfg.Topic != "meshcore/bridge" {
		t.Errorf("expected default topic %q, got %q", "meshcore/bridge", tr.cfg.Topic)
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
