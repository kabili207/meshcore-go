package companion

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec/serial"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
)

// --- test doubles -----------------------------------------------------------

type fakeNode struct {
	pk       [32]byte
	clk      *clock.Clock
	contacts contact.ContactStore
}

func (f *fakeNode) PublicKey() [32]byte            { return f.pk }
func (f *fakeNode) Contacts() contact.ContactStore { return f.contacts }
func (f *fakeNode) Clock() *clock.Clock            { return f.clk }

// stubStore is a minimal ContactStore backed by a slice; only ForEach/Count are
// exercised by the server. The rest satisfy the interface.
type stubStore struct{ list []*contact.ContactInfo }

func (s *stubStore) ForEach(fn func(*contact.ContactInfo) bool) {
	for _, c := range s.list {
		if !fn(c) {
			return
		}
	}
}
func (s *stubStore) Count() int { return len(s.list) }
func (s *stubStore) AddContact(c *contact.ContactInfo) (*contact.ContactInfo, error) {
	return c, nil
}
func (s *stubStore) UpdateContact(*contact.ContactInfo) error         { return nil }
func (s *stubStore) RemoveContact(core.MeshCoreID) error              { return nil }
func (s *stubStore) GetByPubKey(core.MeshCoreID) *contact.ContactInfo { return nil }
func (s *stubStore) SearchByHash(uint8) []*contact.ContactInfo        { return nil }
func (s *stubStore) GetSharedSecret(core.MeshCoreID) ([]byte, error)  { return nil, nil }

// rw adapts a reader and writer into an io.ReadWriter for Serve.
type rw struct {
	io.Reader
	io.Writer
}

// cmd wraps a command payload as an app->device frame.
func cmd(payload ...byte) []byte {
	f, _ := serial.EncodeFrame(serial.FrameAppToNode, payload)
	return f
}

// collectResponses runs Serve over the given command frames and returns the
// decoded response payloads (response code first).
func collectResponses(t *testing.T, s *Server, input []byte) [][]byte {
	t.Helper()
	var out bytes.Buffer
	if err := s.Serve(context.Background(), rw{bytes.NewReader(input), &out}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var frames [][]byte
	fr := serial.NewFrameReader(&out)
	for {
		m, p, err := fr.ReadFrame()
		if err != nil {
			break
		}
		if m != serial.FrameNodeToApp {
			t.Fatalf("response used app->node marker %#x", m)
		}
		frames = append(frames, p)
	}
	return frames
}

func newTestServer(contacts ...*contact.ContactInfo) (*Server, [32]byte) {
	var pk [32]byte
	for i := range pk {
		pk[i] = byte(0x40 + i)
	}
	node := &fakeNode{pk: pk, clk: clock.New(), contacts: &stubStore{list: contacts}}
	s := NewServer(Config{
		Node: node,
		Identity: Identity{
			Name:         "meshy",
			RadioFreqMHz: 915.0,
			RadioBWkHz:   250,
			RadioSF:      11,
			RadioCR:      5,
		},
	})
	return s, pk
}

// --- tests ------------------------------------------------------------------

func TestHandshake(t *testing.T) {
	s, pk := newTestServer()

	input := bytes.Join([][]byte{
		cmd(append([]byte{serial.CmdAppStart, 0, 0, 0, 0, 0, 0, 0}, []byte("MeshMon")...)...),
		cmd(serial.CmdDeviceQuery, 3),
	}, nil)

	resp := collectResponses(t, s, input)
	if len(resp) != 2 {
		t.Fatalf("got %d responses, want 2", len(resp))
	}
	if resp[0][0] != serial.RespCodeSelfInfo {
		t.Errorf("first response code = %d, want SelfInfo", resp[0][0])
	}
	// SelfInfo public key sits at bytes 4..36 and must be the node's key.
	if !bytes.Equal(resp[0][4:36], pk[:]) {
		t.Error("SelfInfo public key does not match node")
	}
	if resp[1][0] != serial.RespCodeDeviceInfo {
		t.Errorf("second response code = %d, want DeviceInfo", resp[1][0])
	}
	if resp[1][1] != serial.CompanionFirmwareVerCode {
		t.Errorf("DeviceInfo ver code = %d, want %d", resp[1][1], serial.CompanionFirmwareVerCode)
	}
}

func TestGetContactsStreams(t *testing.T) {
	var id core.MeshCoreID
	id[0] = 0xAB
	c := &contact.ContactInfo{ID: id, Name: "Bob", Type: serial.AdvTypeChat, OutPathLen: 0xFF, LastMod: 42}
	s, _ := newTestServer(c)

	resp := collectResponses(t, s, cmd(serial.CmdGetContacts))
	if len(resp) != 3 {
		t.Fatalf("got %d responses, want ContactsStart+Contact+End", len(resp))
	}
	if resp[0][0] != serial.RespCodeContactsStart {
		t.Errorf("resp[0] code = %d", resp[0][0])
	}
	if resp[1][0] != serial.RespCodeContact || len(resp[1]) != 148 {
		t.Errorf("resp[1] code=%d len=%d", resp[1][0], len(resp[1]))
	}
	if !bytes.Equal(resp[1][1:33], id[:]) {
		t.Error("contact pubkey mismatch")
	}
	if resp[2][0] != serial.RespCodeEndOfContacts {
		t.Errorf("resp[2] code = %d", resp[2][0])
	}
	// EndOfContacts carries the most-recent lastmod (42).
	if resp[2][1] != 42 {
		t.Errorf("EndOfContacts lastmod = %d, want 42", resp[2][1])
	}
}

func TestGetContactsSinceFilters(t *testing.T) {
	older := &contact.ContactInfo{Name: "old", OutPathLen: 0xFF, LastMod: 10}
	newer := &contact.ContactInfo{Name: "new", OutPathLen: 0xFF, LastMod: 20}
	s, _ := newTestServer(older, newer)

	// since=15: only "new" (lastmod 20) should stream.
	resp := collectResponses(t, s, cmd(serial.CmdGetContacts, 15, 0, 0, 0))
	contacts := 0
	for _, r := range resp {
		if r[0] == serial.RespCodeContact {
			contacts++
		}
	}
	if contacts != 1 {
		t.Errorf("streamed %d contacts, want 1 (since filter)", contacts)
	}
}

func TestUnsupportedCommandReturnsErr(t *testing.T) {
	s, _ := newTestServer()
	// CmdReboot (19) is not implemented in phase 1.
	resp := collectResponses(t, s, cmd(serial.CmdReboot))
	if len(resp) != 1 || resp[0][0] != serial.RespCodeErr {
		t.Fatalf("expected single Err response, got %v", resp)
	}
	if resp[0][1] != serial.ErrCodeUnsupportedCmd {
		t.Errorf("err code = %d, want UnsupportedCmd", resp[0][1])
	}
}

func TestGetBattAndStorage(t *testing.T) {
	s, _ := newTestServer()
	resp := collectResponses(t, s, cmd(serial.CmdGetBattAndStorage))
	if len(resp) != 1 || resp[0][0] != serial.RespCodeBattAndStorage || len(resp[0]) != 11 {
		t.Fatalf("expected 11-byte BattAndStorage, got %v", resp)
	}
	// Default battery is 4200 mV (little-endian at offset 1).
	if mv := uint16(resp[0][1]) | uint16(resp[0][2])<<8; mv != 4200 {
		t.Errorf("battery = %d mV, want 4200", mv)
	}
}

func TestGetChannelPublic(t *testing.T) {
	s, _ := newTestServer()
	resp := collectResponses(t, s, cmd(serial.CmdGetChannel, 0))
	if len(resp) != 1 || resp[0][0] != serial.RespCodeChannelInfo || len(resp[0]) != 50 {
		t.Fatalf("expected 50-byte ChannelInfo, got %v", resp)
	}
	if resp[0][1] != 0 || string(resp[0][2:8]) != "Public" {
		t.Errorf("channel 0 = idx %d name %q", resp[0][1], resp[0][2:34])
	}
	if !bytes.Equal(resp[0][34:50], crypto.DefaultChannelKey) {
		t.Error("channel 0 secret is not the Public PSK")
	}
}

func TestGetChannelOutOfRangeNotFound(t *testing.T) {
	s, _ := newTestServer() // default MaxGroupChannels = 8
	resp := collectResponses(t, s, cmd(serial.CmdGetChannel, 99))
	if len(resp) != 1 || resp[0][0] != serial.RespCodeErr || resp[0][1] != serial.ErrCodeNotFound {
		t.Fatalf("expected NotFound err, got %v", resp)
	}
}

func TestSyncNextMessageEmpty(t *testing.T) {
	s, _ := newTestServer()
	resp := collectResponses(t, s, cmd(serial.CmdSyncNextMessage))
	if len(resp) != 1 || resp[0][0] != serial.RespCodeNoMoreMessages {
		t.Fatalf("expected NoMoreMessages, got %v", resp)
	}
}

func TestSetAdvertNameUpdatesSelfInfo(t *testing.T) {
	s, _ := newTestServer()
	// Set a new name, then read SELF_INFO and confirm it reflects the change.
	input := bytes.Join([][]byte{
		cmd(append([]byte{serial.CmdSetAdvertName}, []byte("Renamed")...)...),
		cmd(append([]byte{serial.CmdAppStart, 0, 0, 0, 0, 0, 0, 0}, []byte("app")...)...),
	}, nil)
	resp := collectResponses(t, s, input)
	if len(resp) != 2 || resp[0][0] != serial.RespCodeOK {
		t.Fatalf("SET_ADVERT_NAME did not OK: %v", resp[0])
	}
	if resp[1][0] != serial.RespCodeSelfInfo || string(resp[1][58:]) != "Renamed" {
		t.Errorf("SELF_INFO name = %q, want Renamed", resp[1][58:])
	}
}

func TestGetDeviceTime(t *testing.T) {
	s, _ := newTestServer()
	resp := collectResponses(t, s, cmd(serial.CmdGetDeviceTime))
	if len(resp) != 1 || resp[0][0] != serial.RespCodeCurrTime || len(resp[0]) != 5 {
		t.Fatalf("expected CurrTime response, got %v", resp)
	}
}
