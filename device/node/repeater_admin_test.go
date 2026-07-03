package node

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/transport"
)

// newTestRepeater builds a repeater with the given passwords and a capture
// transport for observing responses.
func newTestRepeater(t *testing.T, adminPw, guestPw string) (*RepeaterNode, *captureTransport) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	n, err := NewRepeater(RepeaterConfig{
		PrivateKey:    ed25519.PrivateKey(kp.PrivateKey),
		AdminPassword: adminPw,
		GuestPassword: guestPw,
	})
	if err != nil {
		t.Fatalf("new repeater: %v", err)
	}
	ct := &captureTransport{}
	n.base.Router.AddTransport(ct, transport.PacketSourceMQTT)
	return n, ct
}

// buildRepeaterLogin builds an ANON_REQ login packet from client to the repeater.
// The login plaintext is timestamp(4) + password(null-terminated) — no syncSince.
func buildRepeaterLogin(t *testing.T, n *RepeaterNode, client *crypto.KeyPair, timestamp uint32, password string) *codec.Packet {
	t.Helper()

	loginData := make([]byte, 4+len(password)+1)
	binary.LittleEndian.PutUint32(loginData[0:4], timestamp)
	copy(loginData[4:], password)

	repeaterPub := n.base.PublicKey()
	secret, err := crypto.ComputeSharedSecret(client.PrivateKey, repeaterPub[:])
	if err != nil {
		t.Fatalf("shared secret: %v", err)
	}
	encrypted, err := crypto.EncryptAddressedWithSecret(loginData, secret)
	if err != nil {
		t.Fatalf("encrypt login: %v", err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)

	var clientPub [32]byte
	copy(clientPub[:], client.PublicKey)
	payload := codec.BuildAnonReqPayload(n.base.ID().Hash(), clientPub, mac, ciphertext)
	return &codec.Packet{
		Header:  (codec.PayloadTypeAnonReq << codec.PHTypeShift) | codec.RouteTypeDirect,
		Payload: payload,
	}
}

func clientID(kp *crypto.KeyPair) core.MeshCoreID {
	var id core.MeshCoreID
	copy(id[:], kp.PublicKey)
	return id
}

func TestRepeaterLogin_Admin(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()

	pkt := buildRepeaterLogin(t, n, client, 100, "adminpw")
	n.base.processPacket(pkt, transport.PacketSourceMQTT)

	c := n.acl.GetClient(clientID(client))
	if c == nil {
		t.Fatal("expected client in ACL after admin login")
	}
	if !c.IsAdmin() {
		t.Errorf("expected admin role, got perms %d", c.Permissions)
	}

	// A RESPONSE packet should have been sent back.
	var resp *codec.Packet
	for _, p := range ct.sent {
		if p.PayloadType() == codec.PayloadTypeResponse {
			resp = p
		}
	}
	if resp == nil {
		t.Error("expected a login response packet")
	}
}

func TestRepeaterLogin_Guest(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()

	pkt := buildRepeaterLogin(t, n, client, 100, "guestpw")
	n.base.processPacket(pkt, transport.PacketSourceMQTT)

	c := n.acl.GetClient(clientID(client))
	if c == nil {
		t.Fatal("expected client in ACL after guest login")
	}
	if !c.IsGuest() {
		t.Errorf("expected guest role, got perms %d", c.Permissions)
	}
}

func TestRepeaterLogin_WrongPassword(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()

	pkt := buildRepeaterLogin(t, n, client, 100, "nope")
	n.base.processPacket(pkt, transport.PacketSourceMQTT)

	if n.acl.GetClient(clientID(client)) != nil {
		t.Error("wrong password should not create an ACL client")
	}
	for _, p := range ct.sent {
		if p.PayloadType() == codec.PayloadTypeResponse {
			t.Error("wrong password should not send a login response")
		}
	}
}

func TestRepeaterLogin_Replay(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()

	// First login at ts=100 succeeds.
	n.base.processPacket(buildRepeaterLogin(t, n, client, 100, "adminpw"), transport.PacketSourceMQTT)
	c := n.acl.GetClient(clientID(client))
	if c == nil {
		t.Fatal("expected client after first login")
	}

	// Replay at ts=100 (not newer) must not update LastTimestamp beyond 100.
	n.base.processPacket(buildRepeaterLogin(t, n, client, 100, "adminpw"), transport.PacketSourceMQTT)
	if c.LastTimestamp != 100 {
		t.Errorf("LastTimestamp = %d, want 100 (replay ignored)", c.LastTimestamp)
	}
}
