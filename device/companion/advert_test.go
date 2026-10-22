package companion

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec/serial"
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
