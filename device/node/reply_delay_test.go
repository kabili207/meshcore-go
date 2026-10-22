package node

import (
	"context"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/device/router"
	"github.com/kabili207/meshcore-go/transport"
)

// Firmware delays replies so the requester's radio has switched back to
// receive. These tests run the router's send queue and time what goes out.

// startedNode returns a node with a running router, a capture transport, and a
// peer contact. A non-nil outPath gives the contact a direct path.
func startedNode(t *testing.T, outPath []byte) (*BaseNode, *captureTransport, *crypto.KeyPair) {
	t.Helper()
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)

	peer := peerKeyPair(t)
	var peerID core.MeshCoreID
	copy(peerID[:], peer.PublicKey)
	c := &contact.ContactInfo{ID: peerID, OutPathLen: contact.PathUnknown}
	if outPath != nil {
		c.OutPath = outPath
		c.OutPathLen = codec.PathInfo{HashSize: 1, HopCount: uint8(len(outPath))}.ToWireByte()
	}
	if _, err := node.contacts.AddContact(c); err != nil {
		t.Fatal(err)
	}

	node.Router.Start(context.Background())
	t.Cleanup(node.Router.Stop)
	return node, ct, peer
}

type sentAt struct {
	payloadType uint8
	at          time.Duration
}

// collectSends polls ct until want packets have gone out, recording each
// packet's type and how long after start it was first seen.
func collectSends(t *testing.T, ct *captureTransport, start time.Time, want int) []sentAt {
	t.Helper()
	var out []sentAt
	for len(out) < want {
		if time.Since(start) > 3*time.Second {
			t.Fatalf("only %d of %d packets were sent", len(out), want)
		}
		sent := ct.snapshot()
		for _, p := range sent[len(out):] {
			out = append(out, sentAt{p.PayloadType(), time.Since(start)})
		}
		time.Sleep(2 * time.Millisecond)
	}
	return out
}

func TestSendReplyDefaultsToServerResponseDelay(t *testing.T) {
	t.Parallel()
	node, ct, peer := startedNode(t, []byte{0x42})
	var peerID core.MeshCoreID
	copy(peerID[:], peer.PublicKey)
	secret, _ := node.contacts.GetSharedSecret(peerID)

	start := time.Now()
	rc := event.ReplyContext{SharedSecret: secret, DirectPath: []byte{0x42}, DirectPathLen: 1}
	if err := node.SendReply(rc, peerID, codec.PayloadTypeResponse, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if len(ct.snapshot()) != 0 {
		t.Fatal("response sent without a delay")
	}
	got := collectSends(t, ct, start, 1)
	if got[0].at < router.ServerResponseDelay {
		t.Errorf("response sent after %v, want at least %v", got[0].at, router.ServerResponseDelay)
	}
}

// With multi-acks on, firmware sends the multipart copy after TXT_ACK_DELAY and
// the ACK itself 300ms later.
func TestTextAckDelayAndMultiAckOrder(t *testing.T) {
	t.Parallel()
	node, ct, peer := startedNode(t, []byte{0x42})
	node.SetExtraAckTransmits(1)

	start := time.Now()
	node.processPacket(buildTxtMsgFrom(t, node, peer, codec.RouteTypeDirect, nil, "hi"), transport.PacketSourceMQTT)
	if len(ct.snapshot()) != 0 {
		t.Fatal("ACK sent without a delay")
	}
	got := collectSends(t, ct, start, 2)
	if got[0].payloadType != codec.PayloadTypeMultipart || got[1].payloadType != codec.PayloadTypeAck {
		t.Fatalf("send order = %v, want the multipart copy, then the ACK", got)
	}
	if got[0].at < router.TxtAckDelay {
		t.Errorf("multipart ACK sent after %v, want at least %v", got[0].at, router.TxtAckDelay)
	}
	if want := router.TxtAckDelay + router.MultiAckSpacing; got[1].at < want {
		t.Errorf("ACK sent after %v, want at least %v", got[1].at, want)
	}
}

func TestFloodTextAckPathReturnDelayed(t *testing.T) {
	t.Parallel()
	node, ct, peer := startedNode(t, nil)

	start := time.Now()
	node.processPacket(buildTxtMsgFrom(t, node, peer, codec.RouteTypeFlood, []byte{0x99}, "hi"), transport.PacketSourceMQTT)
	if len(ct.snapshot()) != 0 {
		t.Fatal("path-return ACK sent without a delay")
	}
	got := collectSends(t, ct, start, 1)
	if got[0].payloadType != codec.PayloadTypePath || got[0].at < router.TxtAckDelay {
		t.Errorf("got %v, want a PATH return after at least %v", got[0], router.TxtAckDelay)
	}
}

// SendACKPayload answers requests such as a room keep-alive, which firmware
// sends after SERVER_RESPONSE_DELAY.
func TestSendACKPayloadDelayed(t *testing.T) {
	t.Parallel()
	node, ct, peer := startedNode(t, []byte{0x42})
	var peerID core.MeshCoreID
	copy(peerID[:], peer.PublicKey)

	start := time.Now()
	node.SendACKPayload(peerID, codec.BuildAckPayload(0x12345678))
	if len(ct.snapshot()) != 0 {
		t.Fatal("ACK sent without a delay")
	}
	got := collectSends(t, ct, start, 1)
	if got[0].at < router.ServerResponseDelay {
		t.Errorf("ACK sent after %v, want at least %v", got[0].at, router.ServerResponseDelay)
	}
}
