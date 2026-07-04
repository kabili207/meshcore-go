package node

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/transport"
)

// findCollidingKey returns a 16-byte channel key whose 1-byte hash equals target
// but that differs from avoid. Group channels are keyed on the first byte of
// SHA256(key), so distinct keys can collide.
func findCollidingKey(t *testing.T, target uint8, avoid []byte) []byte {
	t.Helper()
	key := make([]byte, 16)
	for i := uint32(1); i != 0; i++ {
		binary.LittleEndian.PutUint32(key, i)
		if crypto.ComputeChannelHash(key) == target && !bytes.Equal(key, avoid) {
			return append([]byte(nil), key...)
		}
	}
	t.Fatal("no colliding key found")
	return nil
}

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

// TestBaseNode_GroupTextNonPlainDropped verifies that group text with a non-plain
// type is dropped, matching firmware (group channels only carry plain text).
func TestBaseNode_GroupTextNonPlainDropped(t *testing.T) {
	node, collector := testNode(t)
	key := crypto.DefaultChannelKey
	node.AddChannel(key)

	// Hand-build a GRP_TXT whose type byte is TxtTypeCLI (non-plain).
	plaintext := crypto.BuildGrpTxtPlaintext(1234, "cli-ish")
	plaintext[4] = codec.TxtTypeCLI << 2
	encrypted, err := crypto.EncryptGroupMessage(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt group: %v", err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildGroupPayload(crypto.ComputeChannelHash(key), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeGrpTxt, codec.RouteTypeFlood, payload)

	node.processPacket(pkt, transport.PacketSourceMQTT)
	if len(collector.get()) != 0 {
		t.Error("non-plain group text should be dropped")
	}
}

func TestBaseNode_SendChannelText(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)

	key := crypto.DefaultChannelKey
	hash := node.AddChannel(key)

	if err := node.SendChannelText(key, "broadcast!"); err != nil {
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

// TestBaseNode_SendChannelTextAsRelay verifies the relay-origin send emits a
// GRP_TXT flood seeded with the node's own hash as hop 1, while still carrying
// the correct decrypted text on the channel.
func TestBaseNode_SendChannelTextAsRelay(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)

	key := crypto.DefaultChannelKey
	hash := node.AddChannel(key)

	if err := node.SendChannelTextAsRelay(key, "from meshtastic"); err != nil {
		t.Fatalf("SendChannelTextAsRelay: %v", err)
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
	// The bridge's own hash must appear as the single hop, so downstream nodes
	// see the message as relayed through this repeater rather than originated.
	if sent.HopCount() != 1 {
		t.Fatalf("hop count = %d, want 1", sent.HopCount())
	}
	pub := node.PublicKey()
	if len(sent.Path) != 1 || sent.Path[0] != pub[0] {
		t.Errorf("path = %x, want [%02x]", sent.Path, pub[0])
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
	if msg != "from meshtastic" {
		t.Errorf("sent message = %q, want %q", msg, "from meshtastic")
	}
}

// TestBaseNode_GroupDataReceive verifies a group datagram surfaces both its
// binary payload and its data type.
func TestBaseNode_GroupDataReceive(t *testing.T) {
	node, collector := testNode(t)
	key := crypto.DefaultChannelKey
	hash := node.AddChannel(key)

	plaintext := crypto.BuildGrpDataPlaintext(0x1234, []byte{0xDE, 0xAD, 0xBE, 0xEF})
	encrypted, err := crypto.EncryptGroupMessage(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt group: %v", err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildGroupPayload(crypto.ComputeChannelHash(key), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeGrpData, codec.RouteTypeFlood, payload)

	node.processPacket(pkt, transport.PacketSourceMQTT)

	events := collector.get()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	gd, ok := events[0].(*event.GroupDataReceived)
	if !ok {
		t.Fatalf("expected GroupDataReceived, got %T", events[0])
	}
	if gd.ChannelHash != hash {
		t.Errorf("channel hash = %02x, want %02x", gd.ChannelHash, hash)
	}
	if gd.DataType != 0x1234 {
		t.Errorf("data type = %#x, want 0x1234", gd.DataType)
	}
	if !bytes.Equal(gd.Data, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("data = %x, want deadbeef", gd.Data)
	}
}

// TestBaseNode_GroupTextHashCollision verifies that two channels sharing a hash
// both decode: the second-registered key no longer clobbers the first.
func TestBaseNode_GroupTextHashCollision(t *testing.T) {
	node, collector := testNode(t)
	keyA := crypto.DefaultChannelKey
	hash := crypto.ComputeChannelHash(keyA)
	keyB := findCollidingKey(t, hash, keyA)

	node.AddChannel(keyA)
	node.AddChannel(keyB)

	// Messages on both colliding channels must decode, regardless of order.
	node.processPacket(buildGrpTxt(t, keyB, 1, "from B"), transport.PacketSourceMQTT)
	node.processPacket(buildGrpTxt(t, keyA, 2, "from A"), transport.PacketSourceMQTT)

	events := collector.get()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	got := map[string]bool{}
	for _, e := range events {
		gt, ok := e.(*event.GroupTextReceived)
		if !ok {
			t.Fatalf("expected GroupTextReceived, got %T", e)
		}
		if gt.ChannelHash != hash {
			t.Errorf("channel hash = %02x, want %02x", gt.ChannelHash, hash)
		}
		got[gt.Message] = true
	}
	if !got["from A"] || !got["from B"] {
		t.Errorf("both colliding channels should decode; got %v", got)
	}
}

// TestBaseNode_RemoveChannelByKey verifies removing one key leaves a colliding
// sibling intact.
func TestBaseNode_RemoveChannelByKey(t *testing.T) {
	node, collector := testNode(t)
	keyA := crypto.DefaultChannelKey
	keyB := findCollidingKey(t, crypto.ComputeChannelHash(keyA), keyA)

	node.AddChannel(keyA)
	node.AddChannel(keyB)
	node.RemoveChannel(keyB) // remove only B; A shares the hash and must survive

	node.processPacket(buildGrpTxt(t, keyB, 1, "from B"), transport.PacketSourceMQTT)
	node.processPacket(buildGrpTxt(t, keyA, 2, "from A"), transport.PacketSourceMQTT)

	events := collector.get()
	if len(events) != 1 {
		t.Fatalf("expected only A to decode, got %d events", len(events))
	}
	if gt := events[0].(*event.GroupTextReceived); gt.Message != "from A" {
		t.Errorf("decoded %q, want %q", gt.Message, "from A")
	}
}
