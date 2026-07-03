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

func TestCompanionTelemetry(t *testing.T) {
	comp, compCap := newTestCompanion(t)
	collector := &eventCollector{}
	comp.OnEvent(collector.handler)

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

	tag, err := comp.SendTelemetryReq(serverID)
	if err != nil {
		t.Fatalf("SendTelemetryReq: %v", err)
	}

	// A GET_TELEMETRY REQ should have been sent.
	var req *codec.Packet
	for _, p := range compCap.sent {
		if p.PayloadType() == codec.PayloadTypeReq {
			req = p
		}
	}
	if req == nil {
		t.Fatal("expected a REQ packet")
	}

	// Server responds with [tag][CayenneLPP bytes].
	telemetry := []byte{0x01, 0x67, 0x00, 0xd5} // channel 1, temperature 21.3
	resp := make([]byte, 4+len(telemetry))
	binary.LittleEndian.PutUint32(resp[0:4], tag)
	copy(resp[4:], telemetry)

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

	var tr *event.TelemetryResponse
	for _, e := range collector.get() {
		if x, ok := e.(*event.TelemetryResponse); ok {
			tr = x
		}
	}
	if tr == nil {
		t.Fatal("expected a TelemetryResponse event")
	}
	if tr.From != serverID {
		t.Error("TelemetryResponse.From should be the server")
	}
	// Content carries the telemetry (possibly followed by AES padding, which a
	// CayenneLPP decoder ignores).
	if !bytes.HasPrefix(tr.Data, telemetry) {
		t.Errorf("telemetry data = %x, want prefix %x", tr.Data, telemetry)
	}
}

func TestCompanionTelemetry_UnmatchedTagIgnored(t *testing.T) {
	comp, _ := newTestCompanion(t)
	collector := &eventCollector{}
	comp.OnEvent(collector.handler)

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

	// A response with a tag we never requested must not produce an event.
	resp := make([]byte, 8)
	binary.LittleEndian.PutUint32(resp[0:4], 0xDEAD)
	cpub := comp.base.PublicKey()
	secret, _ := crypto.ComputeSharedSecret(skp.PrivateKey, cpub[:])
	encrypted, _ := crypto.EncryptAddressedWithSecret(resp, secret)
	mac, ciphertext := codec.SplitMAC(encrypted)
	compID := comp.base.ID()
	payload := codec.BuildAddressedPayload(compID.Hash(), serverID.Hash(), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeResponse, codec.RouteTypeDirect, payload)
	comp.base.processPacket(pkt, transport.PacketSourceMQTT)

	for _, e := range collector.get() {
		if _, ok := e.(*event.TelemetryResponse); ok {
			t.Error("unrequested response should not produce a TelemetryResponse")
		}
	}
}
