package node

import (
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/router"
)

// sentAdvert returns the one advert the companion sent, checking its signature.
func sentAdvert(t *testing.T, ct *captureTransport) (*codec.Packet, *codec.AdvertPayload) {
	t.Helper()
	sent := ct.snapshot()
	if len(sent) != 1 || sent[0].PayloadType() != codec.PayloadTypeAdvert {
		t.Fatalf("sent %d packets, want one advert", len(sent))
	}
	adv, err := codec.ParseAdvertPayload(sent[0].Payload)
	if err != nil {
		t.Fatalf("parse advert: %v", err)
	}
	if !crypto.VerifyAdvert(adv) {
		t.Error("advert signature does not verify")
	}
	return sent[0], adv
}

func TestCompanionSendSelfAdvertZeroHop(t *testing.T) {
	c, ct := newTestCompanion(t)
	lat, lon := -37.8136, 144.9631
	err := c.SendSelfAdvert(&codec.AdvertAppData{
		NodeType: codec.NodeTypeChat, Name: "renamed", Lat: &lat, Lon: &lon,
	}, false, router.TransportKey{0x01})
	if err != nil {
		t.Fatalf("SendSelfAdvert: %v", err)
	}
	pkt, adv := sentAdvert(t, ct)
	if !pkt.IsDirect() || pkt.HopCount() != 0 {
		t.Errorf("route %d hops %d, want zero-hop direct", pkt.RouteType(), pkt.HopCount())
	}
	if adv.PubKey != c.base.PublicKey() {
		t.Error("advert is not signed by this node")
	}
	ad := adv.AppData
	if ad == nil || ad.Name != "renamed" || ad.Lat == nil || *ad.Lat != lat || *ad.Lon != lon {
		t.Errorf("app data = %+v, want the name and location given", ad)
	}
}

func TestCompanionSendSelfAdvertFlood(t *testing.T) {
	scope := router.TransportKeyFromRegion("bay")
	for _, tc := range []struct {
		name  string
		scope router.TransportKey
		route uint8
	}{
		{"unscoped", router.TransportKey{}, codec.RouteTypeFlood},
		{"scoped", scope, codec.RouteTypeTransportFlood},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ct := newTestCompanion(t)
			if err := c.SendSelfAdvert(&codec.AdvertAppData{NodeType: codec.NodeTypeChat, Name: "n"}, true, tc.scope); err != nil {
				t.Fatalf("SendSelfAdvert: %v", err)
			}
			pkt, _ := sentAdvert(t, ct)
			if pkt.RouteType() != tc.route || pkt.HopCount() != 0 {
				t.Fatalf("route %d hops %d, want route %d from zero hops", pkt.RouteType(), pkt.HopCount(), tc.route)
			}
			if tc.route == codec.RouteTypeTransportFlood && pkt.TransportCodes[0] != scope.CalcTransportCode(pkt) {
				t.Errorf("transport code %#x, want the scope's code", pkt.TransportCodes[0])
			}
		})
	}
}
