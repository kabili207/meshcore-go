package node

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/transport"
)

// buildRepeaterAdvert builds a signed, zero-hop advert of the given node type.
func buildRepeaterAdvert(t *testing.T, peer *crypto.KeyPair, timestamp uint32, nodeType uint8) *codec.Packet {
	t.Helper()
	var pubKey [32]byte
	copy(pubKey[:], peer.PublicKey)
	appData := &codec.AdvertAppData{NodeType: nodeType, Name: "Node"}
	appDataBytes := codec.BuildAdvertAppData(appData)
	sig, err := crypto.SignAdvert(peer.PrivateKey, pubKey, timestamp, appDataBytes)
	if err != nil {
		t.Fatalf("sign advert: %v", err)
	}
	payload := codec.BuildAdvertPayload(pubKey, timestamp, sig, appData)
	return codec.NewPacket(codec.PayloadTypeAdvert, codec.RouteTypeFlood, payload)
}

func TestRepeaterNeighbor_RecordsZeroHopRepeater(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	peer, _ := crypto.GenerateKeyPair()

	pkt := buildRepeaterAdvert(t, peer, 500, codec.NodeTypeRepeater)
	pkt.SNR = 40
	n.base.processPacket(pkt, transport.PacketSourceMQTT)

	if n.neighbors.count() != 1 {
		t.Fatalf("expected 1 neighbor, got %d", n.neighbors.count())
	}
	snap := n.neighbors.snapshot(neighborOrderNewest)
	if snap[0].id != clientID(peer) {
		t.Error("neighbor id mismatch")
	}
	if snap[0].snr != 40 {
		t.Errorf("snr = %d, want 40", snap[0].snr)
	}
	if snap[0].advertTimestamp != 500 {
		t.Errorf("advertTimestamp = %d, want 500", snap[0].advertTimestamp)
	}
}

func TestRepeaterNeighbor_IgnoresNonRepeater(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	peer, _ := crypto.GenerateKeyPair()

	n.base.processPacket(buildRepeaterAdvert(t, peer, 500, codec.NodeTypeChat), transport.PacketSourceMQTT)

	if n.neighbors.count() != 0 {
		t.Errorf("a chat advert should not become a neighbor, got %d", n.neighbors.count())
	}
}

func TestRepeaterNeighbor_IgnoresMultiHop(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	peer, _ := crypto.GenerateKeyPair()

	pkt := buildRepeaterAdvert(t, peer, 500, codec.NodeTypeRepeater)
	pkt.PathLen = 1 // mode 0, hop count 1 => not directly heard
	pkt.PathHashSize = 1
	pkt.Path = []byte{0xAB}
	n.base.processPacket(pkt, transport.PacketSourceMQTT)

	if n.neighbors.count() != 0 {
		t.Errorf("a multi-hop advert should not become a neighbor, got %d", n.neighbors.count())
	}
}

func TestNeighborTable_EvictsLeastRecentlyHeard(t *testing.T) {
	tbl := newNeighborTable(2)
	id := func(b byte) core.MeshCoreID { var m core.MeshCoreID; m[0] = b; return m }

	tbl.put(id(0x01), 1, 100, 10) // oldest heard
	tbl.put(id(0x02), 1, 200, 20)
	tbl.put(id(0x03), 1, 300, 30) // evicts id 0x01

	if tbl.count() != 2 {
		t.Fatalf("count = %d, want 2", tbl.count())
	}
	for _, n := range tbl.snapshot(neighborOrderNewest) {
		if n.id == id(0x01) {
			t.Error("least-recently-heard neighbor should have been evicted")
		}
	}
}

func TestRepeaterRequest_GetNeighbours(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	n.base.processPacket(buildRepeaterLogin(t, n, client, 100, "adminpw"), transport.PacketSourceMQTT)

	// Two repeater neighbors with different SNR.
	p1, _ := crypto.GenerateKeyPair()
	p2, _ := crypto.GenerateKeyPair()
	a1 := buildRepeaterAdvert(t, p1, 500, codec.NodeTypeRepeater)
	a1.SNR = 20
	a2 := buildRepeaterAdvert(t, p2, 600, codec.NodeTypeRepeater)
	a2.SNR = 40
	n.base.processPacket(a1, transport.PacketSourceMQTT)
	n.base.processPacket(a2, transport.PacketSourceMQTT)

	// version 0, count 10, offset 0, order=strongest, prefix 6, + random blob.
	reqData := []byte{0, 10, 0, 0, neighborOrderStrongest, 6, 0, 0, 0, 0}
	req := buildRepeaterReq(t, n, client, 200, codec.ReqTypeGetNeighbors, reqData)
	n.base.processPacket(req, transport.PacketSourceMQTT)

	resp := lastResponse(ct)
	if resp == nil {
		t.Fatal("expected a neighbours response")
	}
	pt := decryptRepeaterResponse(t, n, client, resp)
	if binary.LittleEndian.Uint32(pt[0:4]) != 200 {
		t.Errorf("tag = %d, want 200", binary.LittleEndian.Uint32(pt[0:4]))
	}
	total := binary.LittleEndian.Uint16(pt[4:6])
	results := binary.LittleEndian.Uint16(pt[6:8])
	if total != 2 || results != 2 {
		t.Fatalf("total=%d results=%d, want 2/2", total, results)
	}

	// Strongest first => p2 (SNR 40). Entry = prefix(6)+heard(4)+snr(1).
	id2 := clientID(p2)
	if !bytes.Equal(pt[8:14], id2[:6]) {
		t.Errorf("first entry prefix = %x, want p2 %x", pt[8:14], id2[:6])
	}
	if int8(pt[18]) != 40 {
		t.Errorf("first entry snr = %d, want 40", int8(pt[18]))
	}
}
