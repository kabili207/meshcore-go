package router

import (
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
)

// scopedPacket builds a TRANSPORT_FLOOD packet carrying the given code.
func scopedPacket(payload []byte, code uint16) *codec.Packet {
	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift) | codec.RouteTypeTransportFlood,
		Payload: payload,
	}
	pkt.TransportCodes[0] = code
	return pkt
}

// allowFlood clears the deny-flood bit so the region participates in FindMatch
// with the RegionDenyFlood mask (new regions deny flood by default).
func allowFlood(r *RegionEntry) { r.Flags &^= RegionDenyFlood }

func TestRegionPutAndFind(t *testing.T) {
	m := NewRegionMap(nil)

	r := m.PutRegion("#us", 0, 0)
	if r == nil {
		t.Fatal("PutRegion returned nil")
	}
	if r.ID != 1 {
		t.Errorf("first region id = %d, want 1", r.ID)
	}
	if r.Flags&RegionDenyFlood == 0 {
		t.Error("new region should deny flood by default")
	}

	// Lookups ignore the '#' prefix.
	if m.FindByName("us") == nil {
		t.Error(`FindByName("us") should match region "#us"`)
	}
	if m.FindByName("#us") == nil {
		t.Error(`FindByName("#us") should match region "#us"`)
	}
	if m.FindByID(1) != r {
		t.Error("FindByID(1) should return the region")
	}
	if m.FindByID(0) != m.Wildcard() {
		t.Error("FindByID(0) should return the wildcard")
	}

	// Re-parenting an existing region returns the same entry.
	parent := m.PutRegion("#na", 0, 0)
	again := m.PutRegion("#us", parent.ID, 0)
	if again == nil || again.Parent != parent.ID {
		t.Error("re-parenting should update parent and return the region")
	}
	if m.Count() != 2 {
		t.Errorf("count = %d, want 2 (re-parent must not add a region)", m.Count())
	}
}

func TestRegionPutRejects(t *testing.T) {
	m := NewRegionMap(nil)

	if m.PutRegion("bad name", 0, 0) != nil {
		t.Error("names with spaces must be rejected")
	}
	r := m.PutRegion("#loop", 0, 0)
	if m.PutRegion("#loop", r.ID, 0) != nil {
		t.Error("a region cannot be its own parent")
	}

	for i := 0; m.Count() < MaxRegionEntries; i++ {
		if m.PutRegion(nthName(i), 0, 0) == nil {
			t.Fatalf("unexpected nil while filling map at %d", i)
		}
	}
	if m.PutRegion("#overflow", 0, 0) != nil {
		t.Error("PutRegion must return nil when the map is full")
	}
}

func TestRegionFindMatch(t *testing.T) {
	m := NewRegionMap(nil)
	region := m.PutRegion("#us", 0, 0)

	key := TransportKeyFromRegion("#us")
	pkt := scopedPacket([]byte{0x01, 0x02, 0x03}, 0)
	pkt.TransportCodes[0] = key.CalcTransportCode(pkt)

	// While the region denies flood, the DENY_FLOOD mask skips it.
	if m.FindMatch(pkt, RegionDenyFlood) != nil {
		t.Error("flood-denied region must not match under the RegionDenyFlood mask")
	}

	allowFlood(region)
	if got := m.FindMatch(pkt, RegionDenyFlood); got != region {
		t.Errorf("FindMatch = %v, want the #us region", got)
	}

	// A packet coded for a different region does not match.
	other := scopedPacket([]byte{0x01, 0x02, 0x03}, TransportKeyFromRegion("#eu").CalcTransportCode(pkt))
	if m.FindMatch(other, RegionDenyFlood) != nil {
		t.Error("packet coded for a different region must not match")
	}
}

func TestRegionFindMatchImplicitEqualsHashtag(t *testing.T) {
	m := NewRegionMap(nil)
	region := m.PutRegion("us", 0, 0) // implicit hashtag region, no '#'
	allowFlood(region)

	// Code computed from the explicit "#us" form must still match the implicit
	// "us" region, since both derive the same key.
	pkt := scopedPacket([]byte{0xAA, 0xBB}, 0)
	pkt.TransportCodes[0] = TransportKeyFromRegion("#us").CalcTransportCode(pkt)

	if m.FindMatch(pkt, RegionDenyFlood) != region {
		t.Error("implicit region should match a code derived from its '#' form")
	}
}

func TestRegionFindMatchPrivate(t *testing.T) {
	m := NewRegionMap(nil)
	region := m.PutRegion("$secret", 0, 0)
	allowFlood(region)

	var privKey TransportKey
	privKey[0] = 0x42
	m.Store().SaveKeysFor(region.ID, []TransportKey{privKey})

	pkt := scopedPacket([]byte{0x09}, 0)
	pkt.TransportCodes[0] = privKey.CalcTransportCode(pkt)

	if m.FindMatch(pkt, RegionDenyFlood) != region {
		t.Error("private region should match its stored key")
	}

	// A name-derived key must NOT match a "$" region.
	if TransportKeyFromRegion("$secret").CalcTransportCode(pkt) == pkt.TransportCodes[0] {
		t.Skip("name-derived key coincidentally equals stored key")
	}
}

func TestRegionHome(t *testing.T) {
	m := NewRegionMap(nil)
	if m.HomeRegion() != m.Wildcard() {
		t.Error("home should default to the wildcard")
	}
	r := m.PutRegion("#home", 0, 0)
	m.SetHomeRegion(r)
	if m.HomeRegion() != r {
		t.Error("HomeRegion should return the region just set")
	}
	m.SetHomeRegion(nil)
	if m.HomeRegion() != m.Wildcard() {
		t.Error("clearing home should revert to the wildcard")
	}
}

func TestRegionRemove(t *testing.T) {
	m := NewRegionMap(nil)
	if m.RemoveRegion(m.Wildcard()) {
		t.Error("removing the wildcard must fail")
	}

	parent := m.PutRegion("#parent", 0, 0)
	child := m.PutRegion("#child", parent.ID, 0)
	if m.RemoveRegion(parent) {
		t.Error("removing a region with children must fail")
	}
	if !m.RemoveRegion(child) {
		t.Error("removing a leaf region should succeed")
	}
	if !m.RemoveRegion(parent) {
		t.Error("removing the now-childless parent should succeed")
	}
	if m.Count() != 0 {
		t.Errorf("count = %d, want 0", m.Count())
	}
}

func TestRegionExportNames(t *testing.T) {
	m := NewRegionMap(nil)
	allowFlood(m.Wildcard())
	us := m.PutRegion("#us", 0, 0)
	allowFlood(us)
	m.PutRegion("#eu", 0, 0) // stays deny-flood

	// Regions permitting flood: wildcard + us (names without '#').
	if got := m.ExportNames(RegionDenyFlood, false); got != "*,us" {
		t.Errorf("ExportNames(allow) = %q, want %q", got, "*,us")
	}
	// Inverted: regions denying flood.
	if got := m.ExportNames(RegionDenyFlood, true); got != "eu" {
		t.Errorf("ExportNames(deny) = %q, want %q", got, "eu")
	}
}

func TestRegionExportHierarchy(t *testing.T) {
	m := NewRegionMap(nil)
	na := m.PutRegion("#na", 0, 0)
	allowFlood(na)
	m.PutRegion("#us", na.ID, 0) // child, deny-flood
	m.SetHomeRegion(na)

	// Wildcard is the indent-0 root (flood-allowed by default); na is its child
	// at indent 1 (home, flood-allowed); us is na's child at indent 2 (deny).
	want := "* F\n" +
		" na^ F\n" +
		"  us\n"
	if got := m.ExportString(); got != want {
		t.Errorf("ExportString =\n%q\nwant\n%q", got, want)
	}
}

func TestRegionMarshalRoundTrip(t *testing.T) {
	m := NewRegionMap(nil)
	na := m.PutRegion("#na", 0, 0)
	allowFlood(na)
	us := m.PutRegion("#us", na.ID, 0)
	m.SetHomeRegion(us)
	m.Wildcard().Flags = RegionDenyFlood

	data := m.MarshalBinary()
	if want := regionHeaderSize + 2*regionEntrySize; len(data) != want {
		t.Fatalf("marshaled size = %d, want %d", len(data), want)
	}

	m2 := NewRegionMap(nil)
	if err := m2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}

	if m2.Count() != 2 {
		t.Fatalf("restored count = %d, want 2", m2.Count())
	}
	if m2.Wildcard().Flags != RegionDenyFlood {
		t.Error("wildcard flags not restored")
	}
	rna := m2.FindByName("na")
	rus := m2.FindByName("us")
	if rna == nil || rus == nil {
		t.Fatal("regions not restored by name")
	}
	if rna.ID != na.ID || rus.ID != us.ID || rus.Parent != na.ID {
		t.Error("region ids/parent not restored")
	}
	if rna.Flags&RegionDenyFlood != 0 {
		t.Error("na should still permit flood after restore")
	}
	if m2.HomeRegion() == nil || m2.HomeRegion().ID != us.ID {
		t.Error("home region not restored")
	}

	// next_id must survive so new ids don't collide with restored ones.
	next := m2.PutRegion("#eu", 0, 0)
	if next.ID <= us.ID {
		t.Errorf("next region id = %d, want > %d", next.ID, us.ID)
	}
}

func TestRegionUnmarshalTooShort(t *testing.T) {
	m := NewRegionMap(nil)
	if err := m.UnmarshalBinary([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Error("expected error for truncated data")
	}
}

func TestRegionMapFloodForwarding(t *testing.T) {
	// Build a repeater whose only flood-permitting region is "#us".
	rm := NewRegionMap(nil)
	us := rm.PutRegion("#us", 0, 0)
	allowFlood(us)
	rm.Wildcard().Flags = RegionDenyFlood // region-only: no unscoped flood

	newRepeater := func() (*Router, *mockTransport) {
		mt := newMockTransport()
		r := New(Config{
			SelfID:         selfID(0xAA),
			ForwardPackets: true,
			RegionMap:      rm,
		})
		r.AddTransport(mt, transport.PacketSourceMQTT)
		return r, mt
	}

	// A scoped flood for #us is forwarded.
	r, mt := newRepeater()
	inRegion := scopedPacket([]byte{0x01, 0x02}, 0)
	inRegion.TransportCodes[0] = TransportKeyFromRegion("#us").CalcTransportCode(inRegion)
	r.HandlePacket(inRegion, transport.PacketSourceSerial)
	if mt.sentCount() != 1 {
		t.Errorf("in-region scoped flood: sent %d, want 1 (forwarded)", mt.sentCount())
	}

	// A scoped flood for a different region is dropped.
	r, mt = newRepeater()
	outRegion := scopedPacket([]byte{0x03, 0x04}, 0)
	outRegion.TransportCodes[0] = TransportKeyFromRegion("#eu").CalcTransportCode(outRegion)
	r.HandlePacket(outRegion, transport.PacketSourceSerial)
	if mt.sentCount() != 0 {
		t.Errorf("out-of-region scoped flood: sent %d, want 0 (dropped)", mt.sentCount())
	}

	// An unscoped flood is dropped because the wildcard denies flood.
	r, mt = newRepeater()
	unscoped := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x05})
	r.HandlePacket(unscoped, transport.PacketSourceSerial)
	if mt.sentCount() != 0 {
		t.Errorf("unscoped flood with wildcard deny: sent %d, want 0 (dropped)", mt.sentCount())
	}
}

func TestRegionMapAllowsUnscopedWhenWildcardPermits(t *testing.T) {
	rm := NewRegionMap(nil) // wildcard defaults to flood-allowed
	mt := newMockTransport()
	r := New(Config{SelfID: selfID(0xAA), ForwardPackets: true, RegionMap: rm})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	unscoped := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x05})
	r.HandlePacket(unscoped, transport.PacketSourceSerial)
	if mt.sentCount() != 1 {
		t.Errorf("unscoped flood with wildcard allow: sent %d, want 1 (forwarded)", mt.sentCount())
	}
}

func nthName(i int) string {
	return "#r" + string(rune('a'+i%26)) + string(rune('0'+i/26))
}
