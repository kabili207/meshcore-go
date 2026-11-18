package node

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/transport"
)

// buildPathFrom builds a PATH from peer giving route as our way to reach it.
func buildPathFrom(t *testing.T, node *BaseNode, peer *crypto.KeyPair, routeType uint8, floodPath, route []byte, extraType uint8, extra []byte) *codec.Packet {
	t.Helper()
	secret, err := crypto.ComputeSharedSecret(peer.PrivateKey, node.publicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := crypto.EncryptAddressedWithSecret(codec.BuildPathContent(route, 1, extraType, extra), secret)
	if err != nil {
		t.Fatal(err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildAddressedPayload(node.id.Hash(), peer.PublicKey[0], mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypePath, routeType, payload)
	pkt.PathLen, pkt.PathHashSize, pkt.Path = uint8(len(floodPath)), 1, floodPath
	return pkt
}

func addPathPeer(t *testing.T, node *BaseNode) (*crypto.KeyPair, core.MeshCoreID) {
	t.Helper()
	peer := peerKeyPair(t)
	var id core.MeshCoreID
	copy(id[:], peer.PublicKey)
	if _, err := node.contacts.AddContact(&contact.ContactInfo{ID: id, OutPathLen: contact.PathUnknown}); err != nil {
		t.Fatal(err)
	}
	return peer, id
}

func sentPaths(ct *captureTransport) []*codec.Packet {
	var out []*codec.Packet
	for _, p := range ct.snapshot() {
		if p.PayloadType() == codec.PayloadTypePath {
			out = append(out, p)
		}
	}
	return out
}

func TestFloodedPathGetsReciprocal(t *testing.T) {
	comp, ct := newTestCompanion(t)
	peer, id := addPathPeer(t, comp.base)
	floodPath, route := []byte{0x11, 0x22}, []byte{0x33, 0x44, 0x55}

	comp.base.processPacket(buildPathFrom(t, comp.base, peer, codec.RouteTypeFlood, floodPath, route, codec.PayloadTypeAck, make([]byte, 4)), transport.PacketSourceMQTT)

	if got := comp.base.contacts.GetByPubKey(id); !bytes.Equal(got.OutPath, route) {
		t.Errorf("stored route = %x, want %x", got.OutPath, route)
	}
	sent := sentPaths(ct)
	if len(sent) != 1 {
		t.Fatalf("sent %d PATH packets, want 1", len(sent))
	}
	if !sent[0].IsDirect() || !bytes.Equal(sent[0].Path, route) {
		t.Errorf("reciprocal went route %d via %x, want direct via %x", sent[0].RouteType(), sent[0].Path, route)
	}

	addr, err := codec.ParseAddressedPayload(sent[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := crypto.ComputeSharedSecret(peer.PrivateKey, comp.base.publicKey[:])
	plain, err := crypto.DecryptAddressedWithSecret(codec.PrependMAC(addr.MAC, addr.Ciphertext), secret)
	if err != nil {
		t.Fatal(err)
	}
	content, err := codec.ParsePathContent(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content.Path, floodPath) || content.ExtraType != pathExtraNone {
		t.Errorf("reciprocal content = %x type %#x, want %x type %#x", content.Path, content.ExtraType, floodPath, pathExtraNone)
	}
}

func TestDirectPathGetsNoReciprocal(t *testing.T) {
	comp, ct := newTestCompanion(t)
	peer, _ := addPathPeer(t, comp.base)
	comp.base.processPacket(buildPathFrom(t, comp.base, peer, codec.RouteTypeDirect, nil, []byte{0x33}, pathExtraNone, make([]byte, 4)), transport.PacketSourceMQTT)
	if sent := sentPaths(ct); len(sent) != 0 {
		t.Errorf("sent %d PATH packets, want none", len(sent))
	}
}

func TestOnlyCompanionsReciprocate(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)
	peer, _ := addPathPeer(t, node)
	node.processPacket(buildPathFrom(t, node, peer, codec.RouteTypeFlood, []byte{0x11}, []byte{0x33}, pathExtraNone, make([]byte, 4)), transport.PacketSourceMQTT)
	if sent := sentPaths(ct); len(sent) != 0 {
		t.Errorf("sent %d PATH packets, want none", len(sent))
	}
}

func TestPathDiscoveryResponseGetsNoReciprocal(t *testing.T) {
	comp, ct := newTestCompanion(t)
	peer, id := addPathPeer(t, comp.base)
	if err := comp.SendPathDiscovery(id); err != nil {
		t.Fatal(err)
	}
	extra := binary.LittleEndian.AppendUint32(nil, comp.pendingDiscovery.Load())
	extra = append(extra, 0x01)
	response := func() *codec.Packet {
		return buildPathFrom(t, comp.base, peer, codec.RouteTypeFlood, []byte{0x11}, []byte{0x33}, codec.PayloadTypeResponse, extra)
	}

	comp.base.processPacket(response(), transport.PacketSourceMQTT)
	if sent := sentPaths(ct); len(sent) != 0 {
		t.Fatalf("discovery response got %d PATH packets, want none", len(sent))
	}

	// The tag is used up, so the same response is now an ordinary PATH.
	comp.base.processPacket(response(), transport.PacketSourceMQTT)
	if sent := sentPaths(ct); len(sent) != 1 {
		t.Errorf("sent %d PATH packets, want 1", len(sent))
	}
}

func TestZeroHopFloodGetsPathReturn(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)
	peer, _ := addPathPeer(t, node)

	node.processPacket(buildTxtMsgFrom(t, node, peer, codec.RouteTypeFlood, nil, "hi"), transport.PacketSourceMQTT)

	if sent := sentPaths(ct); len(sent) != 1 {
		t.Fatalf("sent %d PATH packets, want 1", len(sent))
	}
}
