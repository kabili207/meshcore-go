package router

import (
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
)

func TestChooseReplyScope(t *testing.T) {
	cases := []struct {
		name                    string
		scopeKnown, wasUnscoped bool
		defaultKnown            bool
		want                    ReplyScope
	}{
		{"known scope mirrors it", true, false, false, ReplyScopeRequest},
		{"known scope beats default", true, false, true, ReplyScopeRequest},
		{"unscoped request stays unscoped", false, true, true, ReplyScopeNone},
		{"unknown scope uses default", false, false, true, ReplyScopeDefault},
		{"unknown scope, no default", false, false, false, ReplyScopeNone},
	}

	for _, c := range cases {
		got := ChooseReplyScope(c.scopeKnown, c.wasUnscoped, c.defaultKnown)
		if got != c.want {
			t.Errorf("%s: ChooseReplyScope(%v, %v, %v) = %v, want %v",
				c.name, c.scopeKnown, c.wasUnscoped, c.defaultKnown, got, c.want)
		}
	}
}

// newScopeTestRouter builds a router with one region and an optional default
// reply scope, and returns the region's transport key.
func newScopeTestRouter(t *testing.T, defaultScope TransportKey) (*Router, TransportKey) {
	t.Helper()
	rm := NewRegionMap(nil)
	rm.PutRegion("#alpha", 0, 1)

	r := New(Config{
		RegionMap:         rm,
		DefaultReplyScope: defaultScope,
	})
	return r, TransportKeyFromRegion("#alpha")
}

// scopedRequest builds a packet as it would arrive scoped to key.
func scopedRequest(key TransportKey) *codec.Packet {
	pkt := codec.NewPacket(codec.PayloadTypeReq, codec.RouteTypeTransportFlood,
		[]byte{0x01, 0x02, 0x03, 0x04})
	pkt.TransportCodes[0] = key.CalcTransportCode(pkt)
	return pkt
}

func TestResolveReplyScope_MirrorsRequestScope(t *testing.T) {
	other := TransportKeyFromRegion("#somewhere-else")
	r, alpha := newScopeTestRouter(t, other)

	got := r.ResolveReplyScope(scopedRequest(alpha))
	if got != alpha {
		t.Error("a request on a known scope should be answered on that scope, not the default")
	}
}

func TestResolveReplyScope_UnscopedRequestStaysUnscoped(t *testing.T) {
	r, _ := newScopeTestRouter(t, TransportKeyFromRegion("#fallback"))

	pkt := codec.NewPacket(codec.PayloadTypeReq, codec.RouteTypeFlood, []byte{0x01})
	if got := r.ResolveReplyScope(pkt); !got.IsNull() {
		t.Error("an un-scoped flood request should be answered un-scoped")
	}
}

func TestResolveReplyScope_DirectRequestUsesDefault(t *testing.T) {
	fallback := TransportKeyFromRegion("#fallback")
	r, _ := newScopeTestRouter(t, fallback)

	// A DIRECT request carries no transport codes, so its scope is unknowable.
	// Answering un-scoped would be dropped by repeaters with flood.max.unscoped=0.
	pkt := codec.NewPacket(codec.PayloadTypeReq, codec.RouteTypeDirect, []byte{0x01})
	if got := r.ResolveReplyScope(pkt); got != fallback {
		t.Error("a direct request should be answered on the default scope")
	}
}

func TestResolveReplyScope_UnknownCodeUsesDefault(t *testing.T) {
	fallback := TransportKeyFromRegion("#fallback")
	r, _ := newScopeTestRouter(t, fallback)

	// Scoped, but the code matches no configured region.
	pkt := codec.NewPacket(codec.PayloadTypeReq, codec.RouteTypeTransportFlood, []byte{0x01})
	pkt.TransportCodes[0] = 0xABCD

	if got := r.ResolveReplyScope(pkt); got != fallback {
		t.Error("an unresolvable scope should fall back to the default")
	}
}

func TestResolveReplyScope_NoDefaultSendsUnscoped(t *testing.T) {
	r, _ := newScopeTestRouter(t, TransportKey{})

	pkt := codec.NewPacket(codec.PayloadTypeReq, codec.RouteTypeDirect, []byte{0x01})
	if got := r.ResolveReplyScope(pkt); !got.IsNull() {
		t.Error("with no default configured the reply should be un-scoped")
	}
}

func TestResolveReplyScope_FallsBackToSendScope(t *testing.T) {
	// A node that only set SendScope keeps using it for replies, so this change
	// does not silently un-scope existing deployments.
	send := TransportKeyFromRegion("#legacy")
	r := New(Config{SendScope: send})

	pkt := codec.NewPacket(codec.PayloadTypeReq, codec.RouteTypeDirect, []byte{0x01})
	if got := r.ResolveReplyScope(pkt); got != send {
		t.Error("DefaultReplyScope unset should fall back to SendScope")
	}
}

func TestResolveReplyScope_NilPacket(t *testing.T) {
	fallback := TransportKeyFromRegion("#fallback")
	r, _ := newScopeTestRouter(t, fallback)

	if got := r.ResolveReplyScope(nil); got != fallback {
		t.Error("a nil request packet should use the default scope")
	}
}

// The end-to-end property: a reply scoped to a mirrored request carries a
// transport code the originating region can match, so it is forwarded rather
// than dropped.
func TestSendFloodReply_CarriesMatchingScope(t *testing.T) {
	rm := NewRegionMap(nil)
	// Regions deny flood by default; clear the flag so FindMatch will accept it.
	rm.PutRegion("#alpha", 0, 1).Flags &^= RegionDenyFlood
	alpha := TransportKeyFromRegion("#alpha")

	r := New(Config{RegionMap: rm})

	req := scopedRequest(alpha)
	reply := codec.NewPacket(codec.PayloadTypeResponse, codec.RouteTypeFlood, []byte{0xAA, 0xBB})
	r.SendFloodReply(reply, req)

	if reply.RouteType() != codec.RouteTypeTransportFlood {
		t.Fatalf("reply route type = %d, want TransportFlood", reply.RouteType())
	}
	if want := alpha.CalcTransportCode(reply); reply.TransportCodes[0] != want {
		t.Errorf("reply transport code = 0x%04x, want 0x%04x", reply.TransportCodes[0], want)
	}
	if rm.FindMatch(reply, RegionDenyFlood) == nil {
		t.Error("the originating region should match the reply's transport code")
	}
}
