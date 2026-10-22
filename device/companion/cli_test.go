package companion

import (
	"context"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec/serial"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
)

func runCLI(t *testing.T, s *Server, command string) string {
	t.Helper()
	resp := collectResponses(t, s, cmd(append([]byte{serial.CmdRunCLICommand}, command...)...))
	if len(resp) != 1 || resp[0][0] != serial.RespCodeCLIReply {
		t.Fatalf("%q: expected CLI_REPLY, got %v", command, resp)
	}
	return string(resp[0][1:])
}

// Reply strings follow firmware's MyMesh::handleCommand (v1.18).
func TestRunCLICommand(t *testing.T) {
	s, _ := newTestServer() // name "meshy", 915 MHz, 250 kHz, SF11, CR5
	s.txPower = 22

	for _, tc := range []struct{ cmd, want string }{
		{"get name", "> meshy"},
		{"  get name", "> meshy"},
		{"07|get name", "07|> meshy"},
		{"set name Hub One", "OK"},
		{"get name", "> Hub One"},
		{"set name bad:name", "Error, bad chars"},
		{"get name", "> Hub One"},
		{"board", "meshcore-go"},
		{"get radio", "> 915.0,250.0,11,5"},
		{"get freq", "> 915.0"},
		{"get tx", "> 22"},
		{"get tz.offset", "> 0"},
		{"set tz.offset -5", "OK"},
		{"get tz.offset", "> -5"},
		{"set tz.offset 15", "Error, must be from -12 to +14"},
		{"set tz.offset 9.7", "OK"},
		{"get tz.offset", "> 9"},
		{"reboot", "Unknown command"},
		{"set tx 20", "Unknown command"},
		{"07|bogus", "07|Unknown command"},
	} {
		if got := runCLI(t, s, tc.cmd); got != tc.want {
			t.Errorf("%q = %q, want %q", tc.cmd, got, tc.want)
		}
	}
	if got := runCLI(t, s, "ver"); got != "v1.18.0 (Build: 15 Oct 2026)" {
		t.Errorf("ver = %q", got)
	}
}

func TestRunCLICommandTooShort(t *testing.T) {
	s, _ := newTestServer()
	resp := collectResponses(t, s, cmd(serial.CmdRunCLICommand, 'x'))
	if resp[0][0] != serial.RespCodeErr || resp[0][1] != serial.ErrCodeIllegalArg {
		t.Errorf("expected IllegalArg, got %v", resp[0])
	}
}

// A TXT_TYPE_CLI_COMMAND from a contact with the remote-CLI flag runs locally
// and is answered with TXT_TYPE_CLI. Without the flag it goes to the app.
func TestRemoteCLI(t *testing.T) {
	for _, tc := range []struct {
		name      string
		flags     uint8
		wantReply bool
	}{
		{"allowed", contact.FlagRemoteCLI, true},
		{"not allowed", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var from core.MeshCoreID
			from[0] = 0x21
			store := &stubStore{list: []*contact.ContactInfo{{ID: from, Flags: tc.flags, OutPathLen: 0xFF}}}
			var handler func(any)
			var sentTo core.MeshCoreID
			var sentText string
			var sentType uint8
			sends := 0
			s := NewServer(Config{
				Node:     &fakeNode{clk: clock.New(), contacts: store},
				Identity: Identity{Name: "meshy"},
				Events:   func(h func(any)) { handler = h },
				SendDM: func(_ context.Context, to core.MeshCoreID, text string, txtType, _ uint8, onAck func()) (bool, error) {
					sends++
					sentTo, sentText, sentType = to, text, txtType
					return false, nil
				},
			})

			handler(&event.TextMessageReceived{Event: event.Event{From: from}, TxtType: serial.TxtTypeCLICommand, Message: "get name", Timestamp: 5})

			queued := collectResponses(t, s, cmd(serial.CmdSyncNextMessage))[0][0] != serial.RespCodeNoMoreMessages
			if tc.wantReply {
				if sends != 1 || sentTo != from || sentText != "> meshy" || sentType != serial.TxtTypeCLI {
					t.Errorf("reply: sends=%d to=%x text=%q type=%d", sends, sentTo[:2], sentText, sentType)
				}
				if queued {
					t.Error("an executed command was also queued for the app")
				}
			} else {
				if sends != 0 {
					t.Error("ran a CLI command from a contact without the remote-CLI flag")
				}
				if !queued {
					t.Error("command from a contact without the flag should be queued for the app")
				}
			}
		})
	}
}
