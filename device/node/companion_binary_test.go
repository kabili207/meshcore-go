package node

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/transport"
)

// addPeer adds a repeater contact to comp and returns its key pair and ID.
func addPeer(t *testing.T, comp *CompanionNode) (*crypto.KeyPair, core.MeshCoreID) {
	t.Helper()
	kp, _ := crypto.GenerateKeyPair()
	var id core.MeshCoreID
	copy(id[:], kp.PublicKey)
	if _, err := comp.base.Contacts().AddContact(&contact.ContactInfo{
		ID: id, Type: codec.NodeTypeRepeater, OutPathLen: contact.PathUnknown,
	}); err != nil {
		t.Fatal(err)
	}
	return kp, id
}

// deliverResponse feeds comp a RESPONSE from peer carrying [tag][body].
func deliverResponse(t *testing.T, comp *CompanionNode, peer *crypto.KeyPair, tag uint32, body []byte) {
	t.Helper()
	resp := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(resp, tag)
	copy(resp[4:], body)

	cpub := comp.base.PublicKey()
	secret, err := crypto.ComputeSharedSecret(peer.PrivateKey, cpub[:])
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := crypto.EncryptAddressedWithSecret(resp, secret)
	if err != nil {
		t.Fatal(err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	var peerID core.MeshCoreID
	copy(peerID[:], peer.PublicKey)
	compID := comp.base.ID()
	payload := codec.BuildAddressedPayload(compID.Hash(), peerID.Hash(), mac, ciphertext)
	comp.base.processPacket(codec.NewPacket(codec.PayloadTypeResponse, codec.RouteTypeDirect, payload), transport.PacketSourceMQTT)
}

func TestCompanionBinaryReq(t *testing.T) {
	comp, compCap := newTestCompanion(t)
	collector := &eventCollector{}
	comp.OnEvent(collector.handler)
	peer, peerID := addPeer(t, comp)

	reqData := []byte{codec.ReqTypeGetNeighbors, 0x00, 0x05}
	tag, flood, err := comp.SendBinaryReq(peerID, reqData)
	if err != nil {
		t.Fatalf("SendBinaryReq: %v", err)
	}
	if !flood {
		t.Error("no path to the peer, so the request should flood")
	}

	// The request is [tag][request data], like firmware's sendRequest.
	var req *codec.Packet
	for _, p := range compCap.sent {
		if p.PayloadType() == codec.PayloadTypeReq {
			req = p
		}
	}
	if req == nil {
		t.Fatal("expected a REQ packet")
	}
	addr, _ := codec.ParseAddressedPayload(req.Payload)
	cpub := comp.base.PublicKey()
	secret, _ := crypto.ComputeSharedSecret(peer.PrivateKey, cpub[:])
	pt, err := crypto.DecryptAddressedWithSecret(codec.PrependMAC(addr.MAC, addr.Ciphertext), secret)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(pt) != tag || !bytes.HasPrefix(pt[4:], reqData) {
		t.Errorf("request plaintext = %x, want tag %08x then %x", pt, tag, reqData)
	}

	deliverResponse(t, comp, peer, tag, []byte{0xAA, 0xBB})

	var br *event.BinaryResponse
	for _, e := range collector.get() {
		switch x := e.(type) {
		case *event.BinaryResponse:
			br = x
		case *event.UnhandledResponse:
			t.Error("a matched binary response was also reported as unhandled")
		}
	}
	if br == nil {
		t.Fatal("expected a BinaryResponse event")
	}
	if br.Tag != tag || br.From != peerID || !bytes.HasPrefix(br.Data, []byte{0xAA, 0xBB}) {
		t.Errorf("BinaryResponse = tag %08x from %s data %x", br.Tag, br.From, br.Data)
	}
}

func TestCompanionBinaryReq_TooLong(t *testing.T) {
	comp, _ := newTestCompanion(t)
	_, peerID := addPeer(t, comp)
	if _, _, err := comp.SendBinaryReq(peerID, make([]byte, codec.MaxPacketPayload-15)); err == nil {
		t.Error("expected an error for request data over the firmware limit")
	}
}

// A response matching no pending request, such as sensor push telemetry, is
// reported so the app can see it (firmware v1.18 onUnhandledResponse).
func TestCompanionUnhandledResponse(t *testing.T) {
	comp, _ := newTestCompanion(t)
	collector := &eventCollector{}
	comp.OnEvent(collector.handler)
	peer, peerID := addPeer(t, comp)

	deliverResponse(t, comp, peer, 0xC0FFEE, []byte{0x01, 0x67, 0x00, 0xd5})

	var ur *event.UnhandledResponse
	for _, e := range collector.get() {
		if x, ok := e.(*event.UnhandledResponse); ok {
			ur = x
		}
	}
	if ur == nil {
		t.Fatal("expected an UnhandledResponse event")
	}
	if ur.Tag != 0xC0FFEE || ur.From != peerID || !bytes.HasPrefix(ur.Content, []byte{0x01, 0x67, 0x00, 0xd5}) {
		t.Errorf("UnhandledResponse = tag %08x from %s content %x", ur.Tag, ur.From, ur.Content)
	}
}

// Firmware treats any response from a server with a pending login as the login
// reply, failures included, so a rejected login must not surface as unhandled.
func TestCompanionLoginFailureNotUnhandled(t *testing.T) {
	comp, _ := newTestCompanion(t)
	collector := &eventCollector{}
	comp.OnEvent(collector.handler)
	peer, peerID := addPeer(t, comp)

	if _, err := comp.SendLogin(peerID, "wrong"); err != nil {
		t.Fatal(err)
	}
	deliverResponse(t, comp, peer, 1, []byte{0x05}) // not RESP_SERVER_LOGIN_OK (0x00)

	for _, e := range collector.get() {
		if _, ok := e.(*event.UnhandledResponse); ok {
			t.Error("a login failure was reported as an unhandled response")
		}
	}

	// The pending login is cleared, so a later push is reported normally.
	deliverResponse(t, comp, peer, 2, []byte{0x01})
	found := false
	for _, e := range collector.get() {
		if _, ok := e.(*event.UnhandledResponse); ok {
			found = true
		}
	}
	if !found {
		t.Error("the pending login wasn't cleared by the failure response")
	}
}

// A rejected login is reported as LoginFailed, which the companion server
// pushes as PUSH_CODE_LOGIN_FAIL.
func TestCompanionLoginFailedEvent(t *testing.T) {
	comp, _ := newTestCompanion(t)
	collector := &eventCollector{}
	comp.OnEvent(collector.handler)
	peer, peerID := addPeer(t, comp)

	if _, err := comp.SendLogin(peerID, "wrong"); err != nil {
		t.Fatal(err)
	}
	deliverResponse(t, comp, peer, 1, []byte{0x05}) // not RESP_SERVER_LOGIN_OK (0x00)

	var lf *event.LoginFailed
	for _, e := range collector.get() {
		if x, ok := e.(*event.LoginFailed); ok {
			lf = x
		}
	}
	if lf == nil || lf.From != peerID {
		t.Errorf("LoginFailed = %+v, want one from the server", lf)
	}
}

// Legacy repeaters answer a good login with a plain "OK", which firmware still
// accepts as success.
func TestCompanionLegacyLoginOK(t *testing.T) {
	comp, _ := newTestCompanion(t)
	collector := &eventCollector{}
	comp.OnEvent(collector.handler)
	peer, peerID := addPeer(t, comp)

	if _, err := comp.SendLogin(peerID, "pw"); err != nil {
		t.Fatal(err)
	}
	deliverResponse(t, comp, peer, 1, []byte("OK"))

	var ok bool
	for _, e := range collector.get() {
		switch e.(type) {
		case *event.LoginResponse:
			ok = true
		case *event.LoginFailed:
			t.Error("legacy OK reported as a failed login")
		}
	}
	if !ok {
		t.Error("expected a LoginResponse for a legacy OK")
	}
}
