package node

import (
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/transport"
)

// Firmware ACKs a TXT_TYPE_SIGNED_PLAIN message (a room server pushing a post)
// the same way as a plain one: inside a path return when it arrived by flood,
// otherwise with sendAckTo, multi-acks included.

func buildSignedFrom(t *testing.T, node *BaseNode, peer *crypto.KeyPair, routeType uint8, path []byte) *codec.Packet {
	t.Helper()
	secret, _ := crypto.ComputeSharedSecret(peer.PrivateKey, node.publicKey[:])
	plaintext := codec.BuildTxtMsgContent(1234, codec.TxtTypeSigned, 0, "posted!", []byte{1, 2, 3, 4})
	encrypted, err := crypto.EncryptAddressedWithSecret(plaintext, secret)
	if err != nil {
		t.Fatal(err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildAddressedPayload(node.id.Hash(), clientID(peer).Hash(), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeTxtMsg, routeType, payload)
	if len(path) > 0 {
		pkt.PathLen, pkt.PathHashSize, pkt.Path = uint8(len(path)), 1, path
	}
	return pkt
}

func TestSignedAck_FloodUsesPathReturn(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)
	peer := peerKeyPair(t)
	if _, err := node.contacts.AddContact(&contact.ContactInfo{ID: clientID(peer), OutPathLen: contact.PathUnknown}); err != nil {
		t.Fatal(err)
	}

	node.processPacket(buildSignedFrom(t, node, peer, codec.RouteTypeFlood, []byte{0x77}), transport.PacketSourceMQTT)

	var ret *codec.Packet
	for _, p := range ct.snapshot() {
		switch p.PayloadType() {
		case codec.PayloadTypePath:
			ret = p
		case codec.PayloadTypeAck:
			t.Error("flood signed message should piggyback the ACK, not send it alone")
		}
	}
	if ret == nil {
		t.Fatal("expected a PATH return")
	}
	addr, _ := codec.ParseAddressedPayload(ret.Payload)
	secret, _ := crypto.ComputeSharedSecret(peer.PrivateKey, node.publicKey[:])
	pt, err := crypto.DecryptAddressedWithSecret(codec.PrependMAC(addr.MAC, addr.Ciphertext), secret)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := codec.ParsePathContent(pt)
	if err != nil {
		t.Fatal(err)
	}
	if pc.ExtraType != codec.PayloadTypeAck || len(pc.Extra) < codec.AckSize {
		t.Errorf("PATH extra = type %d, %d bytes, want a 4-byte ACK", pc.ExtraType, len(pc.Extra))
	}
}

func TestSignedAck_DirectSendsMultiAcks(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)
	node.SetExtraAckTransmits(1)
	peer := peerKeyPair(t)
	var id core.MeshCoreID = clientID(peer)
	if _, err := node.contacts.AddContact(&contact.ContactInfo{ID: id, OutPathLen: 1, OutPath: []byte{0x42}}); err != nil {
		t.Fatal(err)
	}

	node.processPacket(buildSignedFrom(t, node, peer, codec.RouteTypeDirect, nil), transport.PacketSourceMQTT)

	var types []uint8
	for _, p := range ct.snapshot() {
		types = append(types, p.PayloadType())
	}
	if len(types) != 2 || types[0] != codec.PayloadTypeMultipart || types[1] != codec.PayloadTypeAck {
		t.Errorf("sent types %v, want the multipart copy then the ACK", types)
	}
}
