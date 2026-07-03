package node

import (
	"bytes"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/transport"
)

func lastControl(ct *captureTransport) *codec.Packet {
	for i := len(ct.sent) - 1; i >= 0; i-- {
		if ct.sent[i].PayloadType() == codec.PayloadTypeControl {
			return ct.sent[i]
		}
	}
	return nil
}

func countControl(ct *captureTransport) int {
	count := 0
	for _, p := range ct.sent {
		if p.PayloadType() == codec.PayloadTypeControl {
			count++
		}
	}
	return count
}

func TestRepeaterDiscover_RespondsToReq(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")

	tag := uint32(0xABCD1234)
	data := codec.BuildNodeDiscoverReqPayload(1<<codec.NodeTypeRepeater, tag, 0)
	pkt := codec.NewPacket(codec.PayloadTypeControl, codec.RouteTypeDirect, data)
	pkt.SNR = 24
	n.base.processPacket(pkt, transport.PacketSourceMQTT)

	resp := lastControl(ct)
	if resp == nil {
		t.Fatal("expected a discover response")
	}
	ctrl, err := codec.ParseControlPayload(resp.Payload)
	if err != nil {
		t.Fatalf("parse control: %v", err)
	}
	dr, err := codec.ParseDiscoverRespFromControl(ctrl)
	if err != nil {
		t.Fatalf("parse discover resp: %v", err)
	}
	if dr.Tag != tag {
		t.Errorf("resp tag = %08x, want %08x", dr.Tag, tag)
	}
	if dr.NodeType != codec.NodeTypeRepeater {
		t.Errorf("resp node type = %d, want repeater", dr.NodeType)
	}
	if dr.SNR != 24 {
		t.Errorf("resp snr = %d, want 24 (inbound SNR)", dr.SNR)
	}
	id := n.base.ID()
	if !bytes.Equal(dr.PubKey, id[:]) {
		t.Error("resp pubkey should be our identity")
	}
}

func TestRepeaterDiscover_IgnoresNonRepeaterFilter(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")

	// Request filtering for chat nodes only.
	data := codec.BuildNodeDiscoverReqPayload(1<<codec.NodeTypeChat, 1, 0)
	pkt := codec.NewPacket(codec.PayloadTypeControl, codec.RouteTypeDirect, data)
	n.base.processPacket(pkt, transport.PacketSourceMQTT)

	if countControl(ct) != 0 {
		t.Error("repeater should not respond to a non-repeater discover filter")
	}
}

func TestRepeaterDiscover_RateLimited(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")

	// discover_limiter allows 4 per window; a 5th request in the same window is
	// dropped.
	for i := 0; i < 5; i++ {
		data := codec.BuildNodeDiscoverReqPayload(1<<codec.NodeTypeRepeater, uint32(i+1), 0)
		pkt := codec.NewPacket(codec.PayloadTypeControl, codec.RouteTypeDirect, data)
		n.base.processPacket(pkt, transport.PacketSourceMQTT)
	}

	if got := countControl(ct); got != 4 {
		t.Errorf("expected 4 rate-limited responses, got %d", got)
	}
}

func TestRepeaterDiscover_RecordsResponse(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")

	n.SendNodeDiscover()

	// Pull the tag out of the request we just broadcast.
	reqPkt := lastControl(ct)
	if reqPkt == nil {
		t.Fatal("expected a discover request to be sent")
	}
	ctrl, _ := codec.ParseControlPayload(reqPkt.Payload)
	req, err := codec.ParseDiscoverReqFromControl(ctrl)
	if err != nil {
		t.Fatalf("parse our discover req: %v", err)
	}

	// A peer repeater responds with the matching tag.
	peer, _ := crypto.GenerateKeyPair()
	peerID := clientID(peer)
	respData := codec.BuildNodeDiscoverRespPayload(codec.NodeTypeRepeater, 32, req.Tag, peerID[:])
	respPkt := codec.NewPacket(codec.PayloadTypeControl, codec.RouteTypeDirect, respData)
	respPkt.SNR = 32
	n.base.processPacket(respPkt, transport.PacketSourceMQTT)

	if n.neighbors.count() != 1 {
		t.Fatalf("expected 1 neighbor from discover response, got %d", n.neighbors.count())
	}
	snap := n.neighbors.snapshot(neighborOrderNewest)
	if snap[0].id != peerID {
		t.Error("recorded neighbor id mismatch")
	}
	if snap[0].snr != 32 {
		t.Errorf("recorded snr = %d, want 32", snap[0].snr)
	}
}

func TestRepeaterDiscover_IgnoresUnsolicitedResponse(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")

	// A response with no outstanding request (no SendNodeDiscover) is ignored.
	peer, _ := crypto.GenerateKeyPair()
	peerID := clientID(peer)
	respData := codec.BuildNodeDiscoverRespPayload(codec.NodeTypeRepeater, 32, 0x9999, peerID[:])
	respPkt := codec.NewPacket(codec.PayloadTypeControl, codec.RouteTypeDirect, respData)
	n.base.processPacket(respPkt, transport.PacketSourceMQTT)

	if n.neighbors.count() != 0 {
		t.Error("unsolicited discover response should not be recorded")
	}
}
