package node

import (
	"context"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/transport"
)

// A path learned from a peer keeps that peer's hash size. These nodes run the
// default 1-byte PathHashMode while the peer's path uses 2-byte hashes, so
// sending it with our own hash size would turn 2 hops into 4.

var twoByteHops = []byte{0xA1, 0xA2, 0xB1, 0xB2}

func twoBytePathLen() uint8 {
	return codec.PathInfo{HashSize: 2, HopCount: 2}.ToWireByte()
}

// checkTwoByteDirect reports any direct packet in sent that lost the 2-byte
// encoding, and fails if there were none.
func checkTwoByteDirect(t *testing.T, sent []*codec.Packet) {
	t.Helper()
	direct := 0
	for _, p := range sent {
		if !p.IsDirect() {
			continue
		}
		direct++
		if p.PathLen != twoBytePathLen() || p.PathHashSize != 2 || p.HopCount() != 2 {
			t.Errorf("type %d sent with PathLen=%#x hashSize=%d hops=%d, want %#x/2/2",
				p.PayloadType(), p.PathLen, p.PathHashSize, p.HopCount(), twoBytePathLen())
		}
	}
	if direct == 0 {
		t.Fatal("nothing was sent direct")
	}
}

// addTwoBytePeer adds a contact for peer whose stored path uses 2-byte hashes.
func addTwoBytePeer(t *testing.T, store contact.ContactStore, peer *crypto.KeyPair) core.MeshCoreID {
	t.Helper()
	var id core.MeshCoreID
	copy(id[:], peer.PublicKey)
	if _, err := store.AddContact(&contact.ContactInfo{
		ID: id, Type: codec.NodeTypeChat, OutPathLen: twoBytePathLen(), OutPath: twoByteHops,
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestMultiBytePath_Reply(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)

	rc := event.ReplyContext{SharedSecret: make([]byte, 32), DirectPathLen: twoBytePathLen(), DirectPath: twoByteHops}
	if err := node.SendReply(rc, clientID(peerKeyPair(t)), codec.PayloadTypeResponse, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	checkTwoByteDirect(t, ct.snapshot())
}

func TestMultiBytePath_SendToContact(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)
	id := addTwoBytePeer(t, node.contacts, peerKeyPair(t))

	if err := node.SendToContact(id, codec.PayloadTypeTxtMsg, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	checkTwoByteDirect(t, ct.snapshot())
}

func TestMultiBytePath_TextAckWithMultiAck(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)
	node.SetExtraAckTransmits(1)
	peer := peerKeyPair(t)
	addTwoBytePeer(t, node.contacts, peer)

	node.processPacket(buildTxtMsgFrom(t, node, peer, codec.RouteTypeDirect, nil, "hi"), transport.PacketSourceMQTT)
	checkTwoByteDirect(t, ct.snapshot()) // the multipart copy and the ACK
}

func TestMultiBytePath_SendACKPayload(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)
	id := addTwoBytePeer(t, node.contacts, peerKeyPair(t))

	node.SendACKPayload(id, codec.BuildAckPayload(0x01020304))
	checkTwoByteDirect(t, ct.snapshot())
}

func TestMultiBytePath_CompanionSends(t *testing.T) {
	comp, ct := newTestCompanion(t)
	id := addTwoBytePeer(t, comp.base.Contacts(), peerKeyPair(t))

	if err := comp.SendText(context.Background(), id, "hi"); err != nil {
		t.Fatalf("SendText: %v", err)
	}
	if _, err := comp.SendStatusReq(id); err != nil {
		t.Fatalf("SendStatusReq: %v", err)
	}
	checkTwoByteDirect(t, ct.snapshot())
}
