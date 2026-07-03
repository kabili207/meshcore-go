package node

import (
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/transport"
)

// buildTxtMsgFrom builds an addressed plain TXT_MSG from peer to node. A non-nil
// path (1-byte relay hashes) makes it a flood packet with that many hops.
func buildTxtMsgFrom(t *testing.T, node *BaseNode, peer *crypto.KeyPair, routeType uint8, path []byte, message string) *codec.Packet {
	t.Helper()
	secret, err := crypto.ComputeSharedSecret(peer.PrivateKey, node.publicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	plaintext := codec.BuildTxtMsgContent(uint32(time.Now().Unix()), codec.TxtTypePlain, 0, message, nil)
	encrypted, err := crypto.EncryptAddressedWithSecret(plaintext, secret)
	if err != nil {
		t.Fatal(err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	var peerID core.MeshCoreID
	copy(peerID[:], peer.PublicKey)
	payload := codec.BuildAddressedPayload(node.id.Hash(), peerID.Hash(), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeTxtMsg, routeType, payload)
	if len(path) > 0 {
		pkt.PathLen = uint8(len(path)) // 1-byte hashes: hop count == path length
		pkt.PathHashSize = 1
		pkt.Path = path
	}
	return pkt
}

func TestAutoAck_FloodPiggyback(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)

	peer := peerKeyPair(t)
	var peerID core.MeshCoreID
	copy(peerID[:], peer.PublicKey)
	if _, err := node.contacts.AddContact(&contact.ContactInfo{ID: peerID, OutPathLen: contact.PathUnknown}); err != nil {
		t.Fatal(err)
	}

	pkt := buildTxtMsgFrom(t, node, peer, codec.RouteTypeFlood, []byte{0x99}, "hi")
	node.processPacket(pkt, transport.PacketSourceMQTT)

	var pathPkt, ackPkt *codec.Packet
	for _, p := range ct.sent {
		switch p.PayloadType() {
		case codec.PayloadTypePath:
			pathPkt = p
		case codec.PayloadTypeAck:
			ackPkt = p
		}
	}
	if pathPkt == nil {
		t.Fatal("expected a PATH return for a flood DM")
	}
	if ackPkt != nil {
		t.Error("flood DM should piggyback the ACK, not send a standalone ACK")
	}

	// The PATH return should carry the ACK as its embedded extra.
	addr, err := codec.ParseAddressedPayload(pathPkt.Payload)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := crypto.ComputeSharedSecret(peer.PrivateKey, node.publicKey[:])
	pt, err := crypto.DecryptAddressedWithSecret(codec.PrependMAC(addr.MAC, addr.Ciphertext), secret)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := codec.ParsePathContent(pt)
	if err != nil {
		t.Fatal(err)
	}
	if pc.ExtraType != codec.PayloadTypeAck {
		t.Errorf("path extra type = %d, want ACK (%d)", pc.ExtraType, codec.PayloadTypeAck)
	}
	if len(pc.Extra) < codec.AckSize {
		t.Errorf("expected an embedded ACK, got %d bytes", len(pc.Extra))
	}
}

func TestAutoAck_DirectStandalone(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)

	peer := peerKeyPair(t)
	var peerID core.MeshCoreID
	copy(peerID[:], peer.PublicKey)
	if _, err := node.contacts.AddContact(&contact.ContactInfo{ID: peerID, OutPathLen: contact.PathUnknown}); err != nil {
		t.Fatal(err)
	}

	pkt := buildTxtMsgFrom(t, node, peer, codec.RouteTypeDirect, nil, "hi")
	node.processPacket(pkt, transport.PacketSourceMQTT)

	var pathPkt, ackPkt *codec.Packet
	for _, p := range ct.sent {
		switch p.PayloadType() {
		case codec.PayloadTypePath:
			pathPkt = p
		case codec.PayloadTypeAck:
			ackPkt = p
		}
	}
	if ackPkt == nil {
		t.Fatal("expected a standalone ACK for a direct DM")
	}
	if pathPkt != nil {
		t.Error("direct DM should not send a PATH return")
	}
}

func TestAutoAck_MultiAcks(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	contacts := contact.NewManager(kp.PrivateKey, contact.ManagerConfig{MaxContacts: 32})
	node, err := NewBase(BaseConfig{
		PrivateKey:        kp.PrivateKey,
		Contacts:          contacts,
		ExtraAckTransmits: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)

	peer := peerKeyPair(t)
	var peerID core.MeshCoreID
	copy(peerID[:], peer.PublicKey)
	// Contact with a known direct path so the extra ACKs are sent.
	if _, err := contacts.AddContact(&contact.ContactInfo{ID: peerID, OutPathLen: 1, OutPath: []byte{0x05}}); err != nil {
		t.Fatal(err)
	}

	pkt := buildTxtMsgFrom(t, node, peer, codec.RouteTypeDirect, nil, "hi")
	node.processPacket(pkt, transport.PacketSourceMQTT)

	acks, multiparts := 0, 0
	for _, p := range ct.sent {
		switch p.PayloadType() {
		case codec.PayloadTypeAck:
			acks++
		case codec.PayloadTypeMultipart:
			multiparts++
		}
	}
	if acks != 1 {
		t.Errorf("standalone ACKs = %d, want 1", acks)
	}
	if multiparts != 2 {
		t.Errorf("multipart ACKs = %d, want 2 (ExtraAckTransmits)", multiparts)
	}
}
