package node

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/router"
	"github.com/kabili207/meshcore-go/transport"
)

// anonBody returns the response body (after the 8-byte timestamp+clock header)
// with the AES-ECB zero padding stripped, as a client would parse it.
func anonBody(pt []byte) string {
	if len(pt) < 8 {
		return ""
	}
	return strings.TrimRight(string(pt[8:]), "\x00")
}

// buildAnonInfoReq builds a direct ANON_REQ of the given type (regions/owner/
// clock) carrying a {path-len}{path} reply path (1-byte hashes).
func buildAnonInfoReq(t *testing.T, n *RepeaterNode, client *crypto.KeyPair, timestamp uint32, reqType byte, replyPath []byte) *codec.Packet {
	t.Helper()

	pathLenByte := codec.PathInfo{HashSize: 1, HopCount: uint8(len(replyPath))}.ToWireByte()
	data := make([]byte, 6+len(replyPath))
	binary.LittleEndian.PutUint32(data[0:4], timestamp)
	data[4] = reqType
	data[5] = pathLenByte
	copy(data[6:], replyPath)

	repeaterPub := n.base.PublicKey()
	secret, err := crypto.ComputeSharedSecret(client.PrivateKey, repeaterPub[:])
	if err != nil {
		t.Fatalf("shared secret: %v", err)
	}
	encrypted, err := crypto.EncryptAddressedWithSecret(data, secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
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

func TestRepeaterAnon_Owner(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	n.appData.Name = "Hub"
	n.cfg.OwnerInfo = "operator"
	client, _ := crypto.GenerateKeyPair()

	pkt := buildAnonInfoReq(t, n, client, 100, codec.AnonReqTypeOwner, []byte{0xAA, 0xBB})
	n.base.processPacket(pkt, transport.PacketSourceMQTT)

	resp := lastResponse(ct)
	if resp == nil {
		t.Fatal("no response sent")
	}
	pt := decryptRepeaterResponse(t, n, client, resp)
	if len(pt) < 8 {
		t.Fatalf("response too short: %d", len(pt))
	}
	if got := binary.LittleEndian.Uint32(pt[0:4]); got != 100 {
		t.Errorf("echoed timestamp = %d, want 100", got)
	}
	if got := anonBody(pt); got != "Hub\noperator" {
		t.Errorf("owner body = %q, want %q", got, "Hub\noperator")
	}
}

func TestRepeaterAnon_Clock(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()

	pkt := buildAnonInfoReq(t, n, client, 55, codec.AnonReqTypeBasic, []byte{0x01})
	n.base.processPacket(pkt, transport.PacketSourceMQTT)

	pt := decryptRepeaterResponse(t, n, client, lastResponse(ct))
	if len(pt) < 9 {
		t.Fatalf("clock response len = %d, want >= 9", len(pt))
	}
	if pt[8] != 0x00 {
		t.Errorf("features = %#x, want 0 (forwarding enabled)", pt[8])
	}

	// With forwarding disabled the features byte flips the 0x80 bit.
	n.base.Router.SetForwardPackets(false)
	pkt = buildAnonInfoReq(t, n, client, 56, codec.AnonReqTypeBasic, []byte{0x01})
	n.base.processPacket(pkt, transport.PacketSourceMQTT)
	pt = decryptRepeaterResponse(t, n, client, lastResponse(ct))
	if pt[8] != 0x80 {
		t.Errorf("features = %#x, want 0x80 (forwarding disabled)", pt[8])
	}
}

func TestRepeaterAnon_Regions(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	rm := router.NewRegionMap(nil)
	n.base.Router.SetRegionMap(rm)
	client, _ := crypto.GenerateKeyPair()

	pkt := buildAnonInfoReq(t, n, client, 7, codec.AnonReqTypeRegions, []byte{0xAA})
	n.base.processPacket(pkt, transport.PacketSourceMQTT)

	pt := decryptRepeaterResponse(t, n, client, lastResponse(ct))
	want := rm.ExportNames(router.RegionDenyFlood, false)
	if got := anonBody(pt); got != want {
		t.Errorf("regions body = %q, want %q", got, want)
	}
}

func TestRepeaterAnon_RateLimited(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()

	// anon_limiter allows 4 per window; the 5th direct request is dropped.
	for i := 0; i < 5; i++ {
		pkt := buildAnonInfoReq(t, n, client, uint32(200+i), codec.AnonReqTypeBasic, []byte{0x01})
		n.base.processPacket(pkt, transport.PacketSourceMQTT)
	}
	if got := countResponses(ct); got != 4 {
		t.Errorf("responses = %d, want 4 (rate limited)", got)
	}
}

func TestRepeaterAnon_FloodIgnored(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()

	// Typed anon requests are answered only when direct-routed.
	pkt := buildAnonInfoReq(t, n, client, 9, codec.AnonReqTypeOwner, []byte{0xAA})
	pkt.Header = (pkt.Header &^ codec.PHRouteMask) | codec.RouteTypeFlood
	n.base.processPacket(pkt, transport.PacketSourceMQTT)

	if got := countResponses(ct); got != 0 {
		t.Errorf("responses = %d, want 0 (flood ignored)", got)
	}
}
