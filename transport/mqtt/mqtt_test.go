package mqtt

import (
	"context"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
)

func TestNew_Defaults(t *testing.T) {
	tr := New(Config{
		Broker: "tcp://localhost:1883",
		MeshID: "test",
	})

	if tr.cfg.TopicPrefix != DefaultTopicPrefix {
		t.Errorf("expected default topic prefix %q, got %q", DefaultTopicPrefix, tr.cfg.TopicPrefix)
	}
	if tr.log == nil {
		t.Error("expected logger to be set")
	}
}

func TestNew_CustomConfig(t *testing.T) {
	tr := New(Config{
		Broker:      "tcp://broker.example.com:1883",
		Username:    "user",
		Password:    "pass",
		TopicPrefix: "custom",
		MeshID:      "my-mesh",
	})

	if tr.cfg.TopicPrefix != "custom" {
		t.Errorf("expected topic prefix %q, got %q", "custom", tr.cfg.TopicPrefix)
	}
	if tr.cfg.MeshID != "my-mesh" {
		t.Errorf("expected mesh ID %q, got %q", "my-mesh", tr.cfg.MeshID)
	}
}

func TestStart_MissingBroker(t *testing.T) {
	tr := New(Config{MeshID: "test"})
	err := tr.Start(context.Background())
	if err == nil {
		t.Fatal("expected error with empty broker")
	}
}

func TestStart_MissingMeshID(t *testing.T) {
	tr := New(Config{Broker: "tcp://localhost:1883"})
	err := tr.Start(context.Background())
	if err == nil {
		t.Fatal("expected error with empty mesh ID")
	}
}

func TestSendPacket_NotConnected(t *testing.T) {
	tr := New(Config{
		Broker: "tcp://localhost:1883",
		MeshID: "test",
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
		MeshID: "test",
	})

	if tr.IsConnected() {
		t.Error("expected not connected initially")
	}
}
