package node

import (
	"encoding/binary"
	"testing"

	cayennelpp "github.com/TheThingsNetwork/go-cayenne-lib"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/telemetry"
	"github.com/kabili207/meshcore-go/transport"
)

// telemetryMock records the mask it was queried with and adds one reading.
type telemetryMock struct{ lastMask uint8 }

func (m *telemetryMock) QuerySensors(permissions uint8, enc cayennelpp.Encoder) {
	m.lastMask = permissions
	enc.AddTemperature(telemetry.ChannelSelf, 19.5)
}

func TestRepeaterTelemetry_Admin(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	tp := &telemetryMock{}
	n.cfg.Telemetry = tp
	client, _ := crypto.GenerateKeyPair()
	loginAdmin(t, n, client)

	// reqData[0] = 0x00 → mask ~0 = 0xFF (all).
	req := buildRepeaterReq(t, n, client, 200, codec.ReqTypeGetTelemetry, []byte{0x00, 0x00, 0x00, 0x00})
	n.base.processPacket(req, transport.PacketSourceMQTT)

	resp := lastResponse(ct)
	if resp == nil {
		t.Fatal("expected a telemetry response")
	}
	if tp.lastMask != 0xFF {
		t.Errorf("mask = %#x, want 0xFF (admin, all)", tp.lastMask)
	}
	pt := decryptRepeaterResponse(t, n, client, resp)
	if tag := binary.LittleEndian.Uint32(pt[0:4]); tag != 200 {
		t.Errorf("tag = %d, want 200", tag)
	}
	want := cayennelpp.NewEncoder()
	want.AddTemperature(telemetry.ChannelSelf, 19.5)
	body := want.Bytes()
	if got := pt[4 : 4+len(body)]; string(got) != string(body) {
		t.Errorf("telemetry body = %v, want prefix %v", pt[4:], body)
	}
}

func TestRepeaterTelemetry_GuestMaskZero(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	tp := &telemetryMock{}
	n.cfg.Telemetry = tp
	client, _ := crypto.GenerateKeyPair()
	// Log in as a guest.
	n.base.processPacket(buildRepeaterLogin(t, n, client, 100, "guestpw"), transport.PacketSourceMQTT)

	// Even requesting all (~0x00 = 0xFF), a guest is restricted to mask 0.
	req := buildRepeaterReq(t, n, client, 201, codec.ReqTypeGetTelemetry, []byte{0x00, 0x00, 0x00, 0x00})
	n.base.processPacket(req, transport.PacketSourceMQTT)

	if lastResponse(ct) == nil {
		t.Fatal("expected a telemetry response")
	}
	if tp.lastMask != 0x00 {
		t.Errorf("guest mask = %#x, want 0x00", tp.lastMask)
	}
}

func TestRepeaterTelemetry_NoProvider(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	loginAdmin(t, n, client)

	before := countResponses(ct) // the login already produced a response

	req := buildRepeaterReq(t, n, client, 202, codec.ReqTypeGetTelemetry, []byte{0x00, 0x00, 0x00, 0x00})
	n.base.processPacket(req, transport.PacketSourceMQTT)

	if got := countResponses(ct); got != before {
		t.Errorf("responses = %d, want %d (no provider adds nothing)", got, before)
	}
}
