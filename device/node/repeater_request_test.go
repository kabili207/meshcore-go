package node

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/transport"
)

// buildRepeaterReq builds an addressed REQ packet from a client to the repeater.
func buildRepeaterReq(t *testing.T, n *RepeaterNode, client *crypto.KeyPair, timestamp uint32, reqType uint8, reqData []byte) *codec.Packet {
	t.Helper()
	content := codec.BuildRequestContent(timestamp, reqType, reqData)

	repeaterPub := n.base.PublicKey()
	secret, err := crypto.ComputeSharedSecret(client.PrivateKey, repeaterPub[:])
	if err != nil {
		t.Fatalf("shared secret: %v", err)
	}
	encrypted, err := crypto.EncryptAddressedWithSecret(content, secret)
	if err != nil {
		t.Fatalf("encrypt req: %v", err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	id := clientID(client)
	payload := codec.BuildAddressedPayload(n.base.ID().Hash(), id.Hash(), mac, ciphertext)
	return &codec.Packet{
		Header:  (codec.PayloadTypeReq << codec.PHTypeShift) | codec.RouteTypeDirect,
		Payload: payload,
	}
}

func decryptRepeaterResponse(t *testing.T, n *RepeaterNode, client *crypto.KeyPair, pkt *codec.Packet) []byte {
	t.Helper()
	addr, err := codec.ParseAddressedPayload(pkt.Payload)
	if err != nil {
		t.Fatalf("parse addressed: %v", err)
	}
	repeaterPub := n.base.PublicKey()
	secret, err := crypto.ComputeSharedSecret(client.PrivateKey, repeaterPub[:])
	if err != nil {
		t.Fatalf("shared secret: %v", err)
	}
	pt, err := crypto.DecryptAddressedWithSecret(codec.PrependMAC(addr.MAC, addr.Ciphertext), secret)
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}
	return pt
}

func countResponses(ct *captureTransport) int {
	count := 0
	for _, p := range ct.sent {
		if p.PayloadType() == codec.PayloadTypeResponse {
			count++
		}
	}
	return count
}

func lastResponse(ct *captureTransport) *codec.Packet {
	for i := len(ct.sent) - 1; i >= 0; i-- {
		if ct.sent[i].PayloadType() == codec.PayloadTypeResponse {
			return ct.sent[i]
		}
	}
	return nil
}

func TestRepeaterRequest_GetStatus(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	n.base.processPacket(buildRepeaterLogin(t, n, client, 100, "adminpw"), transport.PacketSourceMQTT)

	req := buildRepeaterReq(t, n, client, 200, codec.ReqTypeGetStats, nil)
	n.base.processPacket(req, transport.PacketSourceMQTT)

	resp := lastResponse(ct)
	if resp == nil {
		t.Fatal("expected a status response")
	}
	pt := decryptRepeaterResponse(t, n, client, resp)
	if len(pt) < 4+RepeaterStatsSize {
		t.Fatalf("response len = %d, want >= %d", len(pt), 4+RepeaterStatsSize)
	}
	if tag := binary.LittleEndian.Uint32(pt[0:4]); tag != 200 {
		t.Errorf("response tag = %d, want 200", tag)
	}
}

func TestRepeaterRequest_AccessListAdmin(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	n.base.processPacket(buildRepeaterLogin(t, n, client, 100, "adminpw"), transport.PacketSourceMQTT)

	req := buildRepeaterReq(t, n, client, 200, codec.ReqTypeGetAccessList, []byte{0, 0})
	n.base.processPacket(req, transport.PacketSourceMQTT)

	resp := lastResponse(ct)
	if resp == nil {
		t.Fatal("expected an access-list response")
	}
	pt := decryptRepeaterResponse(t, n, client, resp)
	if binary.LittleEndian.Uint32(pt[0:4]) != 200 {
		t.Errorf("tag = %d, want 200", binary.LittleEndian.Uint32(pt[0:4]))
	}
	id := clientID(client)
	if !bytes.Equal(pt[4:4+aclPrefixSize], id[:aclPrefixSize]) {
		t.Errorf("entry prefix = %x, want %x", pt[4:4+aclPrefixSize], id[:aclPrefixSize])
	}
	if pt[4+aclPrefixSize] != codec.PermACLAdmin {
		t.Errorf("entry perms = %d, want admin", pt[4+aclPrefixSize])
	}
}

func TestRepeaterRequest_AccessListGuestDenied(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	n.base.processPacket(buildRepeaterLogin(t, n, client, 100, "guestpw"), transport.PacketSourceMQTT)

	before := countResponses(ct) // login OK response
	req := buildRepeaterReq(t, n, client, 200, codec.ReqTypeGetAccessList, []byte{0, 0})
	n.base.processPacket(req, transport.PacketSourceMQTT)

	if countResponses(ct) != before {
		t.Error("guest should not receive an access-list response")
	}
}

func TestRepeaterRequest_NonClientIgnored(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	// Make the client a contact (so the REQ decrypts) but never log in.
	if _, err := n.base.Contacts().AddContact(&contact.ContactInfo{
		ID:         clientID(client),
		OutPathLen: contact.PathUnknown,
	}); err != nil {
		t.Fatal(err)
	}

	req := buildRepeaterReq(t, n, client, 200, codec.ReqTypeGetStats, nil)
	n.base.processPacket(req, transport.PacketSourceMQTT)

	if countResponses(ct) != 0 {
		t.Error("request from a non-ACL client should be ignored")
	}
}
