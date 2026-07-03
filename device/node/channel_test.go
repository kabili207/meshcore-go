package node

import (
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/transport"
)

func buildGrpTxt(t *testing.T, key []byte, timestamp uint32, message string) *codec.Packet {
	t.Helper()
	plaintext := crypto.BuildGrpTxtPlaintext(timestamp, message)
	encrypted, err := crypto.EncryptGroupMessage(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt group: %v", err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildGroupPayload(crypto.ComputeChannelHash(key), mac, ciphertext)
	return codec.NewPacket(codec.PayloadTypeGrpTxt, codec.RouteTypeFlood, payload)
}

func TestBaseNode_GroupTextReceive(t *testing.T) {
	node, collector := testNode(t)
	key := crypto.DefaultChannelKey
	hash := node.AddChannel(key)

	node.processPacket(buildGrpTxt(t, key, 1234, "hello channel"), transport.PacketSourceMQTT)

	events := collector.get()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	gt, ok := events[0].(*event.GroupTextReceived)
	if !ok {
		t.Fatalf("expected GroupTextReceived, got %T", events[0])
	}
	if gt.Message != "hello channel" {
		t.Errorf("message = %q, want %q", gt.Message, "hello channel")
	}
	if gt.ChannelHash != hash {
		t.Errorf("channel hash = %02x, want %02x", gt.ChannelHash, hash)
	}
}

func TestBaseNode_GroupTextUnknownChannelIgnored(t *testing.T) {
	node, collector := testNode(t)
	// Channel not registered.
	node.processPacket(buildGrpTxt(t, crypto.DefaultChannelKey, 1234, "hi"), transport.PacketSourceMQTT)
	if len(collector.get()) != 0 {
		t.Error("group text for an unregistered channel should be ignored")
	}
}

func TestBaseNode_SendChannelText(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)

	key := crypto.DefaultChannelKey
	hash := node.AddChannel(key)

	if err := node.SendChannelText(hash, "broadcast!"); err != nil {
		t.Fatalf("SendChannelText: %v", err)
	}

	var sent *codec.Packet
	for _, p := range ct.sent {
		if p.PayloadType() == codec.PayloadTypeGrpTxt {
			sent = p
		}
	}
	if sent == nil {
		t.Fatal("expected a GRP_TXT packet to be sent")
	}
	grp, err := codec.ParseGroupPayload(sent.Payload)
	if err != nil {
		t.Fatalf("parse group payload: %v", err)
	}
	if grp.ChannelHash != hash {
		t.Errorf("channel hash = %02x, want %02x", grp.ChannelHash, hash)
	}
	plaintext, err := crypto.DecryptGroupMessage(codec.PrependMAC(grp.MAC, grp.Ciphertext), key)
	if err != nil {
		t.Fatalf("decrypt sent message: %v", err)
	}
	_, _, msg, err := crypto.ParseGrpTxtPlaintext(plaintext)
	if err != nil {
		t.Fatalf("parse plaintext: %v", err)
	}
	if msg != "broadcast!" {
		t.Errorf("sent message = %q, want %q", msg, "broadcast!")
	}
}

func TestBaseNode_SendChannelTextUnknown(t *testing.T) {
	node, _ := testNode(t)
	if err := node.SendChannelText(0x42, "x"); err == nil {
		t.Error("expected an error sending on an unregistered channel")
	}
}
