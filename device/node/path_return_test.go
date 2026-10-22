package node

import (
	"bytes"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/transport"
)

// A flood from peer A reaches us through R1 then R2, so its path reads
// [R1, R2]: relays append their hash. That is A's route to us, and firmware's
// createPathReturn sends it back unchanged. A uses it as-is (Mesh.cpp sends
// straight down a received PATH's path), and each relay pops its own hash
// from the front. Reversing it would send A's first hop to R2, which isn't
// A's neighbor. Our own route back to A is the reversed path, which starts
// at our neighbor R2.
func TestPathReturn_CarriesPathAsReceived(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashSize uint8
		path     []byte // [R1, R2] as received
		reversed []byte // [R2, R1]
	}{
		{"1-byte hashes", 1, []byte{0x11, 0x22}, []byte{0x22, 0x11}},
		{"2-byte hashes", 2, []byte{0xA1, 0xA2, 0xB1, 0xB2}, []byte{0xB1, 0xB2, 0xA1, 0xA2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node, _ := testNode(t)
			ct := &captureTransport{}
			node.Router.AddTransport(ct, transport.PacketSourceMQTT)
			peer := peerKeyPair(t)
			var peerID core.MeshCoreID
			copy(peerID[:], peer.PublicKey)
			if _, err := node.contacts.AddContact(&contact.ContactInfo{ID: peerID, OutPathLen: contact.PathUnknown}); err != nil {
				t.Fatal(err)
			}

			pathLen := codec.PathInfo{HashSize: tc.hashSize, HopCount: 2}.ToWireByte()
			pkt := buildTxtMsgFrom(t, node, peer, codec.RouteTypeFlood, tc.path, "hi")
			pkt.PathLen, pkt.PathHashSize = pathLen, tc.hashSize
			node.processPacket(pkt, transport.PacketSourceMQTT)

			var ret *codec.Packet
			for _, p := range ct.snapshot() {
				if p.PayloadType() == codec.PayloadTypePath {
					ret = p
				}
			}
			if ret == nil {
				t.Fatal("expected a PATH return")
			}
			addr, err := codec.ParseAddressedPayload(ret.Payload)
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
			if pc.PathLen != pathLen || !bytes.Equal(pc.Path, tc.path) {
				t.Errorf("PATH return carries %#x/%x, want the path as received %#x/%x", pc.PathLen, pc.Path, pathLen, tc.path)
			}

			// Our own stored route back to the peer is the reverse.
			stored := node.contacts.GetByPubKey(peerID)
			if stored.OutPathLen != pathLen || !bytes.Equal(stored.OutPath, tc.reversed) {
				t.Errorf("stored route = %#x/%x, want %#x/%x", stored.OutPathLen, stored.OutPath, pathLen, tc.reversed)
			}
		})
	}
}
