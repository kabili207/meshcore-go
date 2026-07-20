package node

import (
	"bytes"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/transport"
)

func TestCompanionResetPath(t *testing.T) {
	comp, _ := newTestCompanion(t)
	skp, _ := crypto.GenerateKeyPair()
	var id core.MeshCoreID
	copy(id[:], skp.PublicKey)

	ct, err := comp.base.Contacts().AddContact(&contact.ContactInfo{
		ID:         id,
		OutPathLen: 1,
		OutPath:    []byte{0x05},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ct.HasDirectPath() {
		t.Fatal("precondition: contact should have a direct path")
	}

	comp.ResetPath(id)
	if ct.HasDirectPath() {
		t.Error("ResetPath should clear the direct path")
	}
}

func TestCompanionSendPathDiscovery(t *testing.T) {
	comp, compCap := newTestCompanion(t)
	skp, _ := crypto.GenerateKeyPair()
	var id core.MeshCoreID
	copy(id[:], skp.PublicKey)

	// Give the contact a direct path — discovery must flood anyway.
	if _, err := comp.base.Contacts().AddContact(&contact.ContactInfo{
		ID:         id,
		OutPathLen: 1,
		OutPath:    []byte{0x05},
	}); err != nil {
		t.Fatal(err)
	}

	if err := comp.SendPathDiscovery(id); err != nil {
		t.Fatalf("SendPathDiscovery: %v", err)
	}

	var req *codec.Packet
	for _, p := range compCap.sent {
		if p.PayloadType() == codec.PayloadTypeReq {
			req = p
		}
	}
	if req == nil {
		t.Fatal("expected a REQ packet")
	}
	if !req.IsFlood() {
		t.Error("path discovery should flood even with a known direct path")
	}
	addr, err := codec.ParseAddressedPayload(req.Payload)
	if err != nil {
		t.Fatal(err)
	}
	cpub := comp.base.PublicKey()
	secret, _ := crypto.ComputeSharedSecret(skp.PrivateKey, cpub[:])
	pt, err := crypto.DecryptAddressedWithSecret(codec.PrependMAC(addr.MAC, addr.Ciphertext), secret)
	if err != nil {
		t.Fatal(err)
	}
	if pt[4] != codec.ReqTypeGetTelemetry {
		t.Errorf("request type = %d, want GET_TELEMETRY (%d)", pt[4], codec.ReqTypeGetTelemetry)
	}
}

func TestCompanionSendTrace(t *testing.T) {
	comp, compCap := newTestCompanion(t)

	path := []byte{0xAA, 0xBB} // two 1-byte relay hashes
	const tag = 0xCAFEBABE
	if err := comp.SendTrace(tag, 0x12345678, 0x00, path); err != nil {
		t.Fatalf("SendTrace: %v", err)
	}

	var tr *codec.Packet
	for _, p := range compCap.sent {
		if p.PayloadType() == codec.PayloadTypeTrace {
			tr = p
		}
	}
	if tr == nil {
		t.Fatal("expected a TRACE packet")
	}
	if tr.PathLen != 0 {
		t.Errorf("trace PathLen should start at 0, got %d", tr.PathLen)
	}
	parsed, err := codec.ParseTracePayload(tr.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Tag != tag {
		t.Errorf("tag = %08x, want %08x", parsed.Tag, tag)
	}
	if parsed.AuthCode != 0x12345678 {
		t.Errorf("auth = %08x, want 0x12345678", parsed.AuthCode)
	}
	if !bytes.Equal(parsed.PathHashes, path) {
		t.Errorf("path hashes = %x, want %x", parsed.PathHashes, path)
	}
}

func TestCompanionTraceReceived(t *testing.T) {
	comp, _ := newTestCompanion(t)
	collector := &eventCollector{}
	comp.OnEvent(collector.handler)

	// A completed trace: no remaining relay hashes, two hops of SNR collected.
	payload := codec.BuildTracePayload(0xABCD, 0x1111, 0x00, nil)
	pkt := codec.NewPacket(codec.PayloadTypeTrace, codec.RouteTypeDirect, payload)
	pkt.PathLen = 2
	pkt.Path = []byte{20, 40}

	comp.base.processPacket(pkt, transport.PacketSourceMQTT)

	var tr *event.TraceReceived
	for _, e := range collector.get() {
		if x, ok := e.(*event.TraceReceived); ok {
			tr = x
		}
	}
	if tr == nil {
		t.Fatal("expected a TraceReceived event")
	}
	if tr.Tag != 0xABCD {
		t.Errorf("tag = %04x, want abcd", tr.Tag)
	}
	if len(tr.SNRs) != 2 || tr.SNRs[0] != 20 || tr.SNRs[1] != 40 {
		t.Errorf("SNRs = %v, want [20 40]", tr.SNRs)
	}
}
