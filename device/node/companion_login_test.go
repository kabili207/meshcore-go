package node

import (
	"crypto/ed25519"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/transport"
)

func newTestCompanion(t *testing.T) (*CompanionNode, *captureTransport) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	c, err := NewCompanion(CompanionConfig{PrivateKey: ed25519.PrivateKey(kp.PrivateKey)})
	if err != nil {
		t.Fatalf("new companion: %v", err)
	}
	ct := &captureTransport{}
	c.base.Router.AddTransport(ct, transport.PacketSourceMQTT)
	return c, ct
}

func TestCompanionSendLogin_RepeaterAccepts(t *testing.T) {
	rep, _ := newTestRepeater(t, "adminpw", "guestpw")
	comp, compCap := newTestCompanion(t)

	// The companion knows the repeater as a contact.
	repID := rep.base.ID()
	if _, err := comp.base.Contacts().AddContact(&contact.ContactInfo{
		ID:         repID,
		Type:       codec.NodeTypeRepeater,
		OutPathLen: contact.PathUnknown,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := comp.SendLogin(repID, "adminpw"); err != nil {
		t.Fatalf("SendLogin: %v", err)
	}

	// Feed the companion's ANON_REQ login to the repeater.
	var anon *codec.Packet
	for _, p := range compCap.sent {
		if p.PayloadType() == codec.PayloadTypeAnonReq {
			anon = p
		}
	}
	if anon == nil {
		t.Fatal("expected an ANON_REQ login packet to be sent")
	}
	rep.base.processPacket(anon, transport.PacketSourceMQTT)

	// The repeater should have logged the companion in as admin.
	c := rep.acl.GetClient(comp.base.ID())
	if c == nil {
		t.Fatal("repeater did not register the companion after login")
	}
	if !c.IsAdmin() {
		t.Errorf("expected admin role, got perms %d", c.Permissions)
	}
}

func TestCompanionLoginResponse(t *testing.T) {
	comp, _ := newTestCompanion(t)
	collector := &eventCollector{}
	comp.OnEvent(collector.handler)

	// A server the companion will "log in" to.
	skp, _ := crypto.GenerateKeyPair()
	var serverID core.MeshCoreID
	copy(serverID[:], skp.PublicKey)
	if _, err := comp.base.Contacts().AddContact(&contact.ContactInfo{
		ID:         serverID,
		Type:       codec.NodeTypeRepeater,
		OutPathLen: contact.PathUnknown,
	}); err != nil {
		t.Fatal(err)
	}

	// Record a pending login (also exercises the send path with no transport).
	if _, err := comp.SendLogin(serverID, "pw"); err != nil {
		t.Fatalf("SendLogin: %v", err)
	}

	// Build a login-OK RESPONSE from the server to the companion.
	resp := make([]byte, 13)
	resp[4] = codec.RespServerLoginOK
	resp[7] = codec.PermACLAdmin
	cpub := comp.base.PublicKey()
	secret, err := crypto.ComputeSharedSecret(skp.PrivateKey, cpub[:])
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := crypto.EncryptAddressedWithSecret(resp, secret)
	if err != nil {
		t.Fatal(err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	compID := comp.base.ID()
	payload := codec.BuildAddressedPayload(compID.Hash(), serverID.Hash(), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeResponse, codec.RouteTypeDirect, payload)

	comp.base.processPacket(pkt, transport.PacketSourceMQTT)

	var lr *event.LoginResponse
	for _, e := range collector.get() {
		if x, ok := e.(*event.LoginResponse); ok {
			lr = x
		}
	}
	if lr == nil {
		t.Fatal("expected a LoginResponse event")
	}
	if lr.Permissions != codec.PermACLAdmin {
		t.Errorf("permissions = %d, want admin", lr.Permissions)
	}
	if lr.From != serverID {
		t.Error("LoginResponse.From should be the server")
	}
	if !comp.IsConnected(serverID) {
		t.Error("expected the server to be tracked as connected")
	}
}

func TestCompanionSendKeepAlive(t *testing.T) {
	comp, compCap := newTestCompanion(t)

	skp, _ := crypto.GenerateKeyPair()
	var serverID core.MeshCoreID
	copy(serverID[:], skp.PublicKey)
	if _, err := comp.base.Contacts().AddContact(&contact.ContactInfo{
		ID:         serverID,
		Type:       codec.NodeTypeRoom,
		OutPathLen: contact.PathUnknown,
	}); err != nil {
		t.Fatal(err)
	}

	if err := comp.SendKeepAlive(serverID); err != nil {
		t.Fatalf("SendKeepAlive: %v", err)
	}

	var req *codec.Packet
	for _, p := range compCap.sent {
		if p.PayloadType() == codec.PayloadTypeReq {
			req = p
		}
	}
	if req == nil {
		t.Fatal("expected a REQ (keepalive) packet")
	}
	// Decrypt and confirm it is a keepalive request.
	addr, err := codec.ParseAddressedPayload(req.Payload)
	if err != nil {
		t.Fatal(err)
	}
	cpub := comp.base.PublicKey()
	secret, err := crypto.ComputeSharedSecret(skp.PrivateKey, cpub[:])
	if err != nil {
		t.Fatal(err)
	}
	pt, err := crypto.DecryptAddressedWithSecret(codec.PrependMAC(addr.MAC, addr.Ciphertext), secret)
	if err != nil {
		t.Fatal(err)
	}
	if pt[4] != codec.ReqTypeKeepalive {
		t.Errorf("request type = %d, want keepalive (%d)", pt[4], codec.ReqTypeKeepalive)
	}
}
