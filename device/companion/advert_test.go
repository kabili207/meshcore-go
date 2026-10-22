package companion

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/codec/serial"
	"github.com/kabili207/meshcore-go/device/router"
)

func setLatLon(lat, lon int32, extra ...byte) []byte {
	p := []byte{serial.CmdSetAdvertLatLon}
	p = binary.LittleEndian.AppendUint32(p, uint32(lat))
	p = binary.LittleEndian.AppendUint32(p, uint32(lon))
	return cmd(append(p, extra...)...)
}

var appStart = cmd(append([]byte{serial.CmdAppStart, 0, 0, 0, 0, 0, 0, 0}, "app"...)...)

// selfInfoLatLon reads the advertised coordinates from a SELF_INFO reply.
func selfInfoLatLon(t *testing.T, si []byte) (lat, lon int32) {
	t.Helper()
	if si[0] != serial.RespCodeSelfInfo {
		t.Fatalf("got %v, want SELF_INFO", si)
	}
	return int32(binary.LittleEndian.Uint32(si[36:40])), int32(binary.LittleEndian.Uint32(si[40:44]))
}

func TestSetAdvertLatLon(t *testing.T) {
	s, _ := newTestServer()
	resp := collectResponses(t, s, bytes.Join([][]byte{
		setLatLon(-37_813_600, 144_963_100),
		appStart,
		setLatLon(90_000_000, -180_000_000, 0x10, 0, 0, 0), // limits, plus the unused altitude
		appStart,
	}, nil))
	wantCodes(t, resp, serial.RespCodeOK, serial.RespCodeSelfInfo, serial.RespCodeOK, serial.RespCodeSelfInfo)
	if lat, lon := selfInfoLatLon(t, resp[1]); lat != -37_813_600 || lon != 144_963_100 {
		t.Errorf("SELF_INFO location = %d,%d, want -37813600,144963100", lat, lon)
	}
	if lat, lon := selfInfoLatLon(t, resp[3]); lat != 90_000_000 || lon != -180_000_000 {
		t.Errorf("SELF_INFO location = %d,%d, want 90000000,-180000000", lat, lon)
	}
}

func TestSetAdvertLatLonRejectsOutOfRange(t *testing.T) {
	s, _ := newTestServer()
	frames := [][]byte{
		setLatLon(90_000_001, 0),
		setLatLon(-90_000_001, 0),
		setLatLon(0, 180_000_001),
		setLatLon(0, -180_000_001),
	}
	for _, f := range frames {
		resp := collectResponses(t, s, f)
		if len(resp) != 1 || resp[0][0] != serial.RespCodeErr || resp[0][1] != serial.ErrCodeIllegalArg {
			t.Errorf("frame %x: got %v, want ILLEGAL_ARG", f, resp)
		}
	}
	resp := collectResponses(t, s, appStart)
	if lat, lon := selfInfoLatLon(t, resp[0]); lat != 0 || lon != 0 {
		t.Errorf("location after rejections = %d,%d, want unchanged 0,0", lat, lon)
	}
}

// Firmware only matches CMD_SET_ADVERT_LATLON with both coordinates present.
func TestSetAdvertLatLonShortFrame(t *testing.T) {
	s, _ := newTestServer()
	resp := collectResponses(t, s, cmd(serial.CmdSetAdvertLatLon, 1, 2, 3, 4, 5, 6, 7))
	if len(resp) != 1 || resp[0][0] != serial.RespCodeErr || resp[0][1] != serial.ErrCodeUnsupportedCmd {
		t.Errorf("got %v, want UNSUPPORTED_CMD", resp)
	}
}

type advertCall struct {
	appData *codec.AdvertAppData
	flood   bool
	scope   router.TransportKey
}

func newAdvertServer(sendErr error) (*Server, *[]advertCall) {
	var calls []advertCall
	s := NewServer(Config{
		Node:     &fakeNode{clk: clock.New(), contacts: &stubStore{}},
		Identity: Identity{Name: "meshy", Lat: 1.5, Lon: -2.25},
		SendSelfAdvert: func(_ context.Context, ad *codec.AdvertAppData, flood bool, scope router.TransportKey) error {
			calls = append(calls, advertCall{ad, flood, scope})
			return sendErr
		},
	})
	return s, &calls
}

// Byte 1 picks a flood (1) or zero-hop (anything else, or absent) advert. A
// flood uses the default scope, never the app's override (firmware
// CMD_SEND_SELF_ADVERT).
func TestSendSelfAdvert(t *testing.T) {
	s, calls := newAdvertServer(nil)
	def := scopeKey(0xD0)
	resp := collectResponses(t, s, bytes.Join([][]byte{
		cmd(append([]byte{serial.CmdSetAdvertName}, "renamed"...)...),
		setDefaultScope("bay", def),
		setScopeKey(scopeKey(0x0E)),
		cmd(serial.CmdSendSelfAdvert),
		cmd(serial.CmdSendSelfAdvert, 0),
		cmd(serial.CmdSendSelfAdvert, 1),
	}, nil))
	wantCodes(t, resp, serial.RespCodeOK, serial.RespCodeOK, serial.RespCodeOK,
		serial.RespCodeOK, serial.RespCodeOK, serial.RespCodeOK)

	if len(*calls) != 3 {
		t.Fatalf("SendSelfAdvert called %d times, want 3", len(*calls))
	}
	for i, wantFlood := range []bool{false, false, true} {
		c := (*calls)[i]
		if c.flood != wantFlood {
			t.Errorf("advert %d flood = %v, want %v", i, c.flood, wantFlood)
		}
		if wantFlood && c.scope != def {
			t.Errorf("flood advert scope = %x, want the default scope", c.scope)
		}
		if c.appData.Name != "renamed" || c.appData.NodeType != codec.NodeTypeChat {
			t.Errorf("advert %d app data = %+v, want the current name as a chat node", i, c.appData)
		}
		if c.appData.Lat != nil || c.appData.Lon != nil {
			t.Errorf("advert %d carries a location the app did not share", i)
		}
	}
}

// CMD_SET_OTHER_PARAMS byte 3 is the advert location policy. When it shares,
// adverts carry the location, and SELF_INFO reports the policy back.
func TestSendSelfAdvertSharesLocation(t *testing.T) {
	s, calls := newAdvertServer(nil)
	resp := collectResponses(t, s, bytes.Join([][]byte{
		setLatLon(-37_813_600, 144_963_100),
		cmd(serial.CmdSetOtherParams, 0, 0, 1),
		cmd(serial.CmdSendSelfAdvert),
		appStart,
		cmd(serial.CmdSetOtherParams, 0, 0, 0),
		cmd(serial.CmdSendSelfAdvert),
		cmd(serial.CmdSetOtherParams, 0, 0), // no policy byte: unchanged
		cmd(serial.CmdSendSelfAdvert),
	}, nil))
	wantCodes(t, resp, serial.RespCodeOK, serial.RespCodeOK, serial.RespCodeOK, serial.RespCodeSelfInfo,
		serial.RespCodeOK, serial.RespCodeOK, serial.RespCodeOK, serial.RespCodeOK)

	if resp[3][45] != 1 {
		t.Errorf("SELF_INFO location policy = %d, want 1", resp[3][45])
	}
	if len(*calls) != 3 {
		t.Fatalf("SendSelfAdvert called %d times, want 3", len(*calls))
	}
	ad := (*calls)[0].appData
	if ad.Lat == nil || ad.Lon == nil || *ad.Lat != -37.8136 || *ad.Lon != 144.9631 {
		t.Errorf("shared advert location = %v,%v, want -37.8136,144.9631", ad.Lat, ad.Lon)
	}
	for _, c := range (*calls)[1:] {
		if c.appData.Lat != nil {
			t.Error("advert carries a location after sharing was turned off")
		}
	}
}

func TestSendSelfAdvertFailure(t *testing.T) {
	s, _ := newAdvertServer(errors.New("no key"))
	resp := collectResponses(t, s, cmd(serial.CmdSendSelfAdvert))
	if len(resp) != 1 || resp[0][0] != serial.RespCodeErr || resp[0][1] != serial.ErrCodeTableFull {
		t.Errorf("got %v, want TABLE_FULL", resp)
	}

	s, _ = newTestServer() // no SendSelfAdvert callback
	resp = collectResponses(t, s, cmd(serial.CmdSendSelfAdvert))
	if len(resp) != 1 || resp[0][0] != serial.RespCodeErr || resp[0][1] != serial.ErrCodeUnsupportedCmd {
		t.Errorf("without a callback: got %v, want UNSUPPORTED_CMD", resp)
	}
}
