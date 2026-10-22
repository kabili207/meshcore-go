package node

import (
	"bytes"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/device/router"
	"github.com/kabili207/meshcore-go/transport"
)

// Firmware's chooseReplyRoute (PR #3106): a direct login from a client already
// on the ACL is answered over the client's stored path, not flooded.
func TestRepeaterLogin_DirectUsesStoredPath(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	loginAdmin(t, n, client)

	stored := []byte{0x31, 0x32}
	c := n.base.Contacts().GetByPubKey(clientID(client))
	c.OutPath = stored
	c.OutPathLen = codec.PathInfo{HashSize: 1, HopCount: 2}.ToWireByte()

	n.base.processPacket(buildRepeaterLogin(t, n, client, 200, "adminpw"), transport.PacketSourceMQTT)

	resp := lastResponse(ct)
	if resp == nil {
		t.Fatal("expected a login response")
	}
	if !resp.IsDirect() || !bytes.Equal(resp.Path, stored) {
		t.Errorf("login response route=%d path=%x, want direct along %x", resp.RouteType(), resp.Path, stored)
	}
}

// A supplied reply path of zero hops is valid and means "reply zero-hop".
func TestRepeaterAnon_ZeroHopSuppliedPath(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()

	n.base.processPacket(buildAnonInfoReq(t, n, client, 7, codec.AnonReqTypeBasic, nil), transport.PacketSourceMQTT)

	resp := lastResponse(ct)
	if resp == nil {
		t.Fatal("expected an anon response")
	}
	if !resp.IsDirect() || resp.HopCount() != 0 {
		t.Errorf("anon response route=%d hops=%d, want direct zero-hop", resp.RouteType(), resp.HopCount())
	}
}

// A reply to a zero-hop contact goes direct with no path, as firmware's
// sendDirect does for out_path_len 0, instead of flooding.
func TestSendReply_ZeroHopDirect(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)
	peer := peerKeyPair(t)

	rc := event.ReplyContext{SharedSecret: make([]byte, 32), DirectPathLen: 0}
	if err := node.SendReply(rc, clientID(peer), codec.PayloadTypeResponse, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	sent := ct.snapshot()
	if len(sent) != 1 || !sent[0].IsDirect() || sent[0].HopCount() != 0 {
		t.Errorf("sent %v, want one direct zero-hop packet", sent)
	}
}

// Anonymous requests get a resolved reply scope like addressed ones, so a
// flooded reply isn't sent unscoped. A direct request uses the default scope.
func TestAnonRequestReplyScope(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	scope := router.TransportKeyFromRegion("#home")
	n.base.Router.SetSendScope(scope)

	var got *event.AnonRequestReceived
	n.base.OnEvent(func(e any) {
		if x, ok := e.(*event.AnonRequestReceived); ok {
			got = x
		}
	})
	client, _ := crypto.GenerateKeyPair()
	n.base.processPacket(buildRepeaterLogin(t, n, client, 100, "adminpw"), transport.PacketSourceMQTT)

	if got == nil {
		t.Fatal("no AnonRequestReceived event")
	}
	if got.Reply.ReplyScope != scope {
		t.Error("anon request reply scope was not resolved")
	}
}
