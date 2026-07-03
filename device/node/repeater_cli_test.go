package node

import (
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/transport"
)

// buildRepeaterCLI builds an addressed CLI (TXT_TYPE_CLI) message from client.
func buildRepeaterCLI(t *testing.T, n *RepeaterNode, client *crypto.KeyPair, cmd string) *codec.Packet {
	t.Helper()
	content := codec.BuildTxtMsgContent(200, codec.TxtTypeCLI, 0, cmd, nil)
	repeaterPub := n.base.PublicKey()
	secret, err := crypto.ComputeSharedSecret(client.PrivateKey, repeaterPub[:])
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := crypto.EncryptAddressedWithSecret(content, secret)
	if err != nil {
		t.Fatal(err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	id := clientID(client)
	payload := codec.BuildAddressedPayload(n.base.ID().Hash(), id.Hash(), mac, ciphertext)
	return &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift) | codec.RouteTypeDirect,
		Payload: payload,
	}
}

// lastCLIReply returns the message text of the last TXT_MSG the repeater sent.
func lastCLIReply(t *testing.T, n *RepeaterNode, client *crypto.KeyPair, ct *captureTransport) (string, bool) {
	t.Helper()
	var reply *codec.Packet
	for _, p := range ct.sent {
		if p.PayloadType() == codec.PayloadTypeTxtMsg {
			reply = p
		}
	}
	if reply == nil {
		return "", false
	}
	pt := decryptRepeaterResponse(t, n, client, reply)
	content, err := codec.ParseTxtMsgContent(pt)
	if err != nil {
		t.Fatalf("parse cli reply: %v", err)
	}
	if content.TxtType != codec.TxtTypeCLI {
		t.Errorf("reply txt type = %d, want CLI", content.TxtType)
	}
	return content.Message, true
}

func loginAdmin(t *testing.T, n *RepeaterNode, client *crypto.KeyPair) {
	t.Helper()
	n.base.processPacket(buildRepeaterLogin(t, n, client, 100, "adminpw"), transport.PacketSourceMQTT)
}

func TestRepeaterCLI_GetRole(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	loginAdmin(t, n, client)

	n.base.processPacket(buildRepeaterCLI(t, n, client, "get role"), transport.PacketSourceMQTT)

	reply, ok := lastCLIReply(t, n, client, ct)
	if !ok {
		t.Fatal("expected a CLI reply")
	}
	if reply != "repeater" {
		t.Errorf("get role = %q, want repeater", reply)
	}
}

func TestRepeaterCLI_SetName(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	loginAdmin(t, n, client)

	n.base.processPacket(buildRepeaterCLI(t, n, client, "set name Hub"), transport.PacketSourceMQTT)

	reply, ok := lastCLIReply(t, n, client, ct)
	if !ok || reply != "OK" {
		t.Fatalf("set name reply = %q (ok=%v), want OK", reply, ok)
	}
	if n.appData.Name != "Hub" {
		t.Errorf("appData.Name = %q, want Hub (advert not updated)", n.appData.Name)
	}
}

func TestRepeaterCLI_FloodMax(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	loginAdmin(t, n, client)

	n.base.processPacket(buildRepeaterCLI(t, n, client, "set flood.max 12"), transport.PacketSourceMQTT)
	if n.base.Router.GetMaxFloodHops() != 12 {
		t.Errorf("flood.max = %d, want 12", n.base.Router.GetMaxFloodHops())
	}
	if reply, _ := lastCLIReply(t, n, client, ct); reply != "OK" {
		t.Errorf("set flood.max reply = %q, want OK", reply)
	}
}

func TestRepeaterCLI_NonAdminDenied(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	// Log in as a guest, not an admin.
	n.base.processPacket(buildRepeaterLogin(t, n, client, 100, "guestpw"), transport.PacketSourceMQTT)

	n.base.processPacket(buildRepeaterCLI(t, n, client, "get role"), transport.PacketSourceMQTT)

	for _, p := range ct.sent {
		if p.PayloadType() == codec.PayloadTypeTxtMsg {
			t.Error("a non-admin CLI command should get no reply")
		}
	}
}
