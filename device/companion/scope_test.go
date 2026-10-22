package companion

import (
	"bytes"
	"testing"

	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec/serial"
	"github.com/kabili207/meshcore-go/device/router"
)

// newScopeServer returns a server whose SetFloodScope calls are recorded.
func newScopeServer() (*Server, *[]router.TransportKey) {
	var calls []router.TransportKey
	s := NewServer(Config{
		Node:          &fakeNode{clk: clock.New(), contacts: &stubStore{}},
		SetFloodScope: func(key router.TransportKey) { calls = append(calls, key) },
	})
	return s, &calls
}

func scopeKey(b byte) router.TransportKey {
	var k router.TransportKey
	for i := range k {
		k[i] = b
	}
	return k
}

func setScopeKey(key router.TransportKey) []byte {
	return cmd(append([]byte{serial.CmdSetFloodScopeKey, 0}, key[:]...)...)
}

func setDefaultScope(name string, key router.TransportKey) []byte {
	p := make([]byte, 1+31+16)
	p[0] = serial.CmdSetDefaultFloodScope
	copy(p[1:32], name)
	copy(p[32:], key[:])
	return cmd(p...)
}

func wantCodes(t *testing.T, resp [][]byte, codes ...byte) {
	t.Helper()
	if len(resp) != len(codes) {
		t.Fatalf("got %d responses, want %d: %v", len(resp), len(codes), resp)
	}
	for i, c := range codes {
		if resp[i][0] != c {
			t.Errorf("response %d = %v, want code %d", i, resp[i], c)
		}
	}
}

// The scope the app's flood traffic uses follows firmware's sendFloodScoped:
// unscoped when the app asked for it, else the override key, else the default
// scope.
func TestFloodScopeResolution(t *testing.T) {
	s, calls := newScopeServer()
	def, override := scopeKey(0xD0), scopeKey(0x0E)

	steps := []struct {
		name  string
		frame []byte
		want  router.TransportKey
	}{
		{"default scope set", setDefaultScope("bay", def), def},
		{"override set", setScopeKey(override), override},
		{"default changed under override", setDefaultScope("city", scopeKey(0xC1)), override},
		{"override cleared", cmd(serial.CmdSetFloodScopeKey, 0), scopeKey(0xC1)},
		{"unscoped requested", cmd(serial.CmdSetFloodScopeKey, 1), router.TransportKey{}},
		{"override set again", setScopeKey(override), override},
		{"default cleared", cmd(serial.CmdSetDefaultFloodScope), override},
		{"override cleared, no default", cmd(serial.CmdSetFloodScopeKey, 0), router.TransportKey{}},
	}
	for _, st := range steps {
		resp := collectResponses(t, s, st.frame)
		if len(resp) != 1 || resp[0][0] != serial.RespCodeOK {
			t.Fatalf("%s: got %v, want OK", st.name, resp)
		}
		if len(*calls) == 0 || (*calls)[len(*calls)-1] != st.want {
			t.Fatalf("%s: scope applied = %v, want %x", st.name, *calls, st.want)
		}
	}
}

func TestGetDefaultFloodScope(t *testing.T) {
	s, _ := newScopeServer()
	key := scopeKey(0xD0)

	resp := collectResponses(t, s, bytes.Join([][]byte{
		cmd(serial.CmdGetDefaultFloodScope),
		setDefaultScope("bay", key),
		cmd(serial.CmdGetDefaultFloodScope),
		cmd(serial.CmdSetDefaultFloodScope),
		cmd(serial.CmdGetDefaultFloodScope),
	}, nil))
	wantCodes(t, resp, serial.RespCodeDefaultFloodScope, serial.RespCodeOK,
		serial.RespCodeDefaultFloodScope, serial.RespCodeOK, serial.RespCodeDefaultFloodScope)

	if len(resp[0]) != 1 {
		t.Errorf("unset scope reply = %v, want the code alone", resp[0])
	}
	if want := serial.EncodeDefaultFloodScope("bay", key[:]); !bytes.Equal(resp[2], want) {
		t.Errorf("set scope reply = %x, want %x", resp[2], want)
	}
	if len(resp[4]) != 1 {
		t.Errorf("cleared scope reply = %v, want the code alone", resp[4])
	}
}

// A name must be 1-30 characters, NUL-terminated within its 31-byte field.
func TestSetDefaultFloodScopeRejectsBadName(t *testing.T) {
	s, calls := newScopeServer()
	for _, name := range []string{"", "0123456789012345678901234567890"} {
		resp := collectResponses(t, s, setDefaultScope(name, scopeKey(0xD0)))
		if len(resp) != 1 || resp[0][0] != serial.RespCodeErr || resp[0][1] != serial.ErrCodeIllegalArg {
			t.Errorf("name %q: got %v, want ILLEGAL_ARG", name, resp)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("rejected names changed the scope: %v", *calls)
	}
	resp := collectResponses(t, s, cmd(serial.CmdGetDefaultFloodScope))
	if len(resp) != 1 || len(resp[0]) != 1 {
		t.Errorf("default scope after rejections = %v, want unset", resp)
	}
}

// Firmware only handles byte 1 values 0 and 1; anything else, or a frame
// without it, falls through to UNSUPPORTED_CMD.
func TestSetFloodScopeKeyBadSubcommand(t *testing.T) {
	s, calls := newScopeServer()
	for _, frame := range [][]byte{cmd(serial.CmdSetFloodScopeKey), cmd(serial.CmdSetFloodScopeKey, 2)} {
		resp := collectResponses(t, s, frame)
		if len(resp) != 1 || resp[0][0] != serial.RespCodeErr || resp[0][1] != serial.ErrCodeUnsupportedCmd {
			t.Errorf("frame %x: got %v, want UNSUPPORTED_CMD", frame, resp)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("bad frames changed the scope: %v", *calls)
	}
}
