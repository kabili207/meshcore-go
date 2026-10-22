package node

import (
	"context"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/cli"
	"github.com/kabili207/meshcore-go/transport"
)

// buildRepeaterCLI builds an addressed CLI (TXT_TYPE_CLI) message from client.
func buildRepeaterCLI(t *testing.T, n *RepeaterNode, client *crypto.KeyPair, cmd string) *codec.Packet {
	t.Helper()
	return buildRepeaterTxt(t, n, client, codec.TxtTypeCLI, cmd)
}

// buildRepeaterTxt builds an addressed TXT_MSG of the given text type from client.
func buildRepeaterTxt(t *testing.T, n *RepeaterNode, client *crypto.KeyPair, txtType uint8, cmd string) *codec.Packet {
	t.Helper()
	content := codec.BuildTxtMsgContent(200, txtType, 0, cmd, nil)
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

// Firmware v1.18 added TXT_TYPE_CLI_COMMAND (3); repeaters treat it like type 1.
func TestRepeaterCLI_CommandTxtType(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	loginAdmin(t, n, client)

	n.base.processPacket(buildRepeaterTxt(t, n, client, codec.TxtTypeCLICommand, "get role"), transport.PacketSourceMQTT)

	reply, ok := lastCLIReply(t, n, client, ct)
	if !ok {
		t.Fatal("expected a CLI reply to a type 3 command")
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

// CLI replies wait cli.ReplyDelay in the send queue, like firmware's
// CLI_REPLY_DELAY_MILLIS, so a requester behind an RF bridge has switched back
// to receive.
func TestRepeaterCLI_ReplyDelayed(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	loginAdmin(t, n, client)

	n.base.Router.Start(context.Background())
	defer n.base.Router.Stop()

	countTxt := func() int {
		c := 0
		for _, p := range ct.snapshot() {
			if p.PayloadType() == codec.PayloadTypeTxtMsg {
				c++
			}
		}
		return c
	}

	start := time.Now()
	n.base.processPacket(buildRepeaterCLI(t, n, client, "get role"), transport.PacketSourceMQTT)
	if countTxt() != 0 {
		t.Fatal("CLI reply went out without the reply delay")
	}
	for countTxt() == 0 {
		if time.Since(start) > 3*time.Second {
			t.Fatal("CLI reply was never sent")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if elapsed := time.Since(start); elapsed < cli.ReplyDelay {
		t.Errorf("CLI reply sent after %v, want at least %v", elapsed, cli.ReplyDelay)
	}
}

// A CLI reply never reuses the command's timestamp. Firmware bumps it, since
// the apps' CLI view keeps command and reply apart by timestamp.
func TestRepeaterCLI_ReplyTimestampDiffers(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	loginAdmin(t, n, client)

	cmdTS := n.base.Clock().GetCurrentTime()
	pkt := buildRepeaterTxt(t, n, client, codec.TxtTypeCLI, "get role")
	// Rebuild with the command stamped at our current time.
	content := codec.BuildTxtMsgContent(cmdTS, codec.TxtTypeCLI, 0, "get role", nil)
	repeaterPub := n.base.PublicKey()
	secret, _ := crypto.ComputeSharedSecret(client.PrivateKey, repeaterPub[:])
	encrypted, _ := crypto.EncryptAddressedWithSecret(content, secret)
	mac, ciphertext := codec.SplitMAC(encrypted)
	pkt.Payload = codec.BuildAddressedPayload(n.base.ID().Hash(), clientID(client).Hash(), mac, ciphertext)
	n.base.processPacket(pkt, transport.PacketSourceMQTT)

	var reply *codec.Packet
	for _, p := range ct.snapshot() {
		if p.PayloadType() == codec.PayloadTypeTxtMsg {
			reply = p
		}
	}
	if reply == nil {
		t.Fatal("expected a CLI reply")
	}
	got, err := codec.ParseTxtMsgContent(decryptRepeaterResponse(t, n, client, reply))
	if err != nil {
		t.Fatal(err)
	}
	if got.Timestamp == cmdTS {
		t.Errorf("reply timestamp %d equals the command's", got.Timestamp)
	}
}

// Firmware's CommonCLI rejects node names containing [ ] \ : , ? *.
func TestRepeaterCLI_SetNameRejectsBadChars(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	loginAdmin(t, n, client)
	n.appData.Name = "Hub"

	n.base.processPacket(buildRepeaterCLI(t, n, client, "set name Hub:2"), transport.PacketSourceMQTT)

	reply, ok := lastCLIReply(t, n, client, ct)
	if !ok || reply != "Error: bad chars" {
		t.Errorf("set name Hub:2 = %q (ok=%v), want Error: bad chars", reply, ok)
	}
	if n.appData.Name != "Hub" {
		t.Errorf("name = %q, want it unchanged", n.appData.Name)
	}
}
