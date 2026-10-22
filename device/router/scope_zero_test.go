package router

import (
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
)

// Transport code 0 carries no scope, so it follows the wildcard region exactly
// like an un-scoped flood. See isUnscoped.

func TestRegionFindMatchCodeZeroFollowsWildcard(t *testing.T) {
	m := NewRegionMap(nil)
	allowFlood(m.PutRegion("#us", 0, 0))
	pkt := scopedPacket([]byte{0x01, 0x02}, 0)

	if got := m.FindMatch(pkt, RegionDenyFlood); got != m.Wildcard() {
		t.Errorf("code 0 with wildcard allowing flood: FindMatch = %v, want the wildcard", got)
	}
	m.Wildcard().Flags = RegionDenyFlood
	if got := m.FindMatch(pkt, RegionDenyFlood); got != nil {
		t.Errorf("code 0 with wildcard denying flood: FindMatch = %v, want nil", got)
	}
}

func TestRegionMapCodeZeroFloodForwarding(t *testing.T) {
	for _, tc := range []struct {
		name     string
		deny     bool
		wantSent int
	}{
		{"wildcard allows", false, 1},
		{"wildcard denies", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rm := NewRegionMap(nil)
			if tc.deny {
				rm.Wildcard().Flags = RegionDenyFlood
			}
			mt := newMockTransport()
			r := New(Config{SelfID: selfID(0xAA), ForwardPackets: true, RegionMap: rm})
			r.AddTransport(mt, transport.PacketSourceMQTT)

			r.HandlePacket(scopedPacket([]byte{0x05}, 0), transport.PacketSourceSerial)
			if mt.sentCount() != tc.wantSent {
				t.Errorf("sent %d, want %d", mt.sentCount(), tc.wantSent)
			}
		})
	}
}

func TestHandlePacket_CodeZeroUnscopedCap(t *testing.T) {
	for _, tc := range []struct {
		name     string
		code     uint16
		wantSent int
	}{
		{"code 0 is capped like un-scoped", 0, 0},
		{"real scope is not capped", 0x1234, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mt := newMockTransport()
			r := New(Config{SelfID: selfID(0xAA), ForwardPackets: true, MaxUnscopedFloodHops: 4})
			r.AddTransport(mt, transport.PacketSourceMQTT)

			pkt := scopedPacket([]byte{0x01}, tc.code)
			pkt.PathLen = 4
			pkt.Path = []byte{1, 2, 3, 4}
			r.HandlePacket(pkt, transport.PacketSourceSerial)
			if mt.sentCount() != tc.wantSent {
				t.Errorf("sent %d, want %d", mt.sentCount(), tc.wantSent)
			}
		})
	}
}

// A validator only filters scoped traffic. Code 0, such as the zero-hop
// {0, 0} contact share, carries no scope and must not be rejected by it.
func TestHandlePacket_CodeZeroSkipsValidator(t *testing.T) {
	r := New(Config{
		SelfID:                selfID(0xAA),
		ValidateTransportCode: func(*codec.Packet) bool { return false },
	})
	dispatched := false
	r.SetPacketHandler(func(*codec.Packet, transport.PacketSource) { dispatched = true })

	share := &codec.Packet{
		Header:  (codec.PayloadTypeAdvert << codec.PHTypeShift) | codec.RouteTypeTransportDirect,
		Payload: []byte{0x01, 0x02, 0x03},
	}
	r.HandlePacket(share, transport.PacketSourceSerial)
	if !dispatched {
		t.Error("code 0 packet was rejected by the transport code validator")
	}
}

func TestResolveReplyScope_CodeZeroRequestStaysUnscoped(t *testing.T) {
	r, _ := newScopeTestRouter(t, TransportKeyFromRegion("#fallback"))

	pkt := codec.NewPacket(codec.PayloadTypeReq, codec.RouteTypeTransportFlood, []byte{0x01})
	if got := r.ResolveReplyScope(pkt); !got.IsNull() {
		t.Error("a code 0 request should be answered un-scoped, like an un-scoped flood")
	}
}
