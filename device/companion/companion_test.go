package companion

import (
	"bytes"
	"context"
	"io"
	"testing"

	"encoding/binary"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec/serial"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
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

// decodeFrames drains all device->app frames from buf, returning their payloads.
func decodeFrames(buf *bytes.Buffer) [][]byte {
	var frames [][]byte
	fr := serial.NewFrameReader(buf)
	for {
		_, p, err := fr.ReadFrame()
		if err != nil {
			break
		}
		frames = append(frames, p)
	}
	return frames
}

func TestSendTextMsgAndConfirm(t *testing.T) {
	var id core.MeshCoreID
	for i := range id {
		id[i] = byte(i + 1)
	}
	c := &contact.ContactInfo{ID: id, Name: "Bob", OutPathLen: 0xFF}

	var gotTo core.MeshCoreID
	var gotText string
	var ack func()
	node := &fakeNode{clk: clock.New(), contacts: &stubStore{list: []*contact.ContactInfo{c}}}
	s := NewServer(Config{
		Node: node,
		SendDM: func(_ context.Context, to core.MeshCoreID, text string, _, _ uint8, onAck func()) (bool, error) {
			gotTo, gotText, ack = to, text, onAck // ack fires later, like a real ACK
			return false, nil
		},
	})

	// [2][txt_type][attempt][ts u32][dest prefix 6][text]
	payload := append([]byte{serial.CmdSendTxtMsg, 0, 0, 0, 0, 0, 0}, id[:6]...)
	payload = append(payload, []byte("hello")...)

	var out bytes.Buffer
	sess := &session{srv: s, w: &out, ctx: context.Background()}
	if err := s.sendTextMsg(sess, payload); err != nil {
		t.Fatalf("sendTextMsg: %v", err)
	}

	if gotTo != id || gotText != "hello" {
		t.Errorf("sendDM got to=%x text=%q", gotTo, gotText)
	}

	// The recipient acknowledges after SENT has already been written.
	ack()

	frames := decodeFrames(&out)
	if len(frames) != 2 {
		t.Fatalf("expected SENT + SEND_CONFIRMED, got %d frames", len(frames))
	}
	if frames[0][0] != serial.RespCodeSent || frames[0][1] != serial.SentTypeDirect {
		t.Errorf("SENT frame = %x", frames[0])
	}
	token := binary.LittleEndian.Uint32(frames[0][2:6])
	if frames[1][0] != serial.PushCodeSendConfirmed {
		t.Fatalf("second frame is not SEND_CONFIRMED: %x", frames[1])
	}
	if ack := binary.LittleEndian.Uint32(frames[1][1:5]); ack != token {
		t.Errorf("SEND_CONFIRMED ack=%d does not match SENT token=%d", ack, token)
	}
}

func TestSendTextMsgUnknownContact(t *testing.T) {
	node := &fakeNode{clk: clock.New(), contacts: &stubStore{}}
	s := NewServer(Config{
		Node:   node,
		SendDM: func(context.Context, core.MeshCoreID, string, uint8, uint8, func()) (bool, error) { return false, nil },
	})
	payload := append([]byte{serial.CmdSendTxtMsg, 0, 0, 0, 0, 0, 0}, []byte{1, 2, 3, 4, 5, 6}...)
	payload = append(payload, 'x')
	resp := collectResponses(t, s, cmd(payload...))
	if resp[0][0] != serial.RespCodeErr || resp[0][1] != serial.ErrCodeNotFound {
		t.Fatalf("expected NotFound, got %v", resp[0])
	}
}

func TestSendTextMsgWithoutSendDM(t *testing.T) {
	s, _ := newTestServer() // no SendDM configured
	payload := append([]byte{serial.CmdSendTxtMsg, 0, 0, 0, 0, 0, 0}, []byte{1, 2, 3, 4, 5, 6}...)
	payload = append(payload, 'x')
	resp := collectResponses(t, s, cmd(payload...))
	if resp[0][0] != serial.RespCodeErr || resp[0][1] != serial.ErrCodeUnsupportedCmd {
		t.Fatalf("expected UnsupportedCmd, got %v", resp[0])
	}
}

func TestIncomingMessageDrain(t *testing.T) {
	var handler func(any)
	node := &fakeNode{clk: clock.New(), contacts: &stubStore{}}
	s := NewServer(Config{Node: node, Events: func(h func(any)) { handler = h }})

	var from core.MeshCoreID
	from[0], from[5] = 0xAB, 0xCD
	handler(&event.TextMessageReceived{Event: event.Event{From: from}, Message: "hi", TxtType: 0, Timestamp: 999})

	// pre-V3 (appTargetVer 0): RESP_CODE_CONTACT_MSG_RECV.
	resp := collectResponses(t, s, cmd(serial.CmdSyncNextMessage))
	if resp[0][0] != serial.RespCodeContactMsgRecv {
		t.Fatalf("expected ContactMsgRecv, got %v", resp[0])
	}
	if !bytes.Equal(resp[0][1:7], from[:6]) {
		t.Errorf("sender prefix = %x, want %x", resp[0][1:7], from[:6])
	}
	if string(resp[0][13:]) != "hi" {
		t.Errorf("text = %q", resp[0][13:])
	}

	// Queue now empty.
	resp = collectResponses(t, s, cmd(serial.CmdSyncNextMessage))
	if resp[0][0] != serial.RespCodeNoMoreMessages {
		t.Errorf("expected NoMoreMessages after drain, got %v", resp[0])
	}
}

func TestIncomingMessagePushesMsgWaiting(t *testing.T) {
	var handler func(any)
	node := &fakeNode{clk: clock.New(), contacts: &stubStore{}}
	s := NewServer(Config{Node: node, Events: func(h func(any)) { handler = h }})

	var out bytes.Buffer
	sess := &session{srv: s, w: &out, ctx: context.Background()}
	s.addSession(sess)

	handler(&event.TextMessageReceived{Event: event.Event{}, Message: "ping"})

	frames := decodeFrames(&out)
	if len(frames) != 1 || frames[0][0] != serial.PushCodeMsgWaiting {
		t.Fatalf("expected a MsgWaiting push, got %v", frames)
	}
}

func TestSendChannelMsg(t *testing.T) {
	var gotIdx uint8
	var gotText string
	node := &fakeNode{clk: clock.New(), contacts: &stubStore{}}
	s := NewServer(Config{
		Node: node,
		SendChannel: func(_ context.Context, idx uint8, text string) error {
			gotIdx, gotText = idx, text
			return nil
		},
	})

	// [3][txt_type][channel_idx][sender_ts u32][text]
	resp := collectResponses(t, s, cmd(serial.CmdSendChannelTxtMsg, 0, 0, 0, 0, 0, 0, 'h', 'i'))
	// Firmware replies RESP_CODE_OK to a channel send, not RESP_CODE_SENT.
	if len(resp) != 1 || resp[0][0] != serial.RespCodeOK {
		t.Fatalf("expected OK, got %x", resp[0])
	}
	if gotIdx != 0 || gotText != "hi" {
		t.Errorf("SendChannel got idx=%d text=%q", gotIdx, gotText)
	}
}

func TestSendChannelWithoutCallback(t *testing.T) {
	s, _ := newTestServer() // no SendChannel
	resp := collectResponses(t, s, cmd(serial.CmdSendChannelTxtMsg, 0, 0, 0, 0, 0, 0, 'x'))
	if resp[0][0] != serial.RespCodeErr || resp[0][1] != serial.ErrCodeUnsupportedCmd {
		t.Fatalf("expected UnsupportedCmd, got %v", resp[0])
	}
}

func TestIncomingChannelDrain(t *testing.T) {
	var handler func(any)
	node := &fakeNode{clk: clock.New(), contacts: &stubStore{}}
	s := NewServer(Config{Node: node, Events: func(h func(any)) { handler = h }})

	publicHash := crypto.ComputeChannelHash(crypto.DefaultChannelKey)
	handler(&event.GroupTextReceived{Event: event.Event{}, ChannelHash: publicHash, Message: "hey"})

	resp := collectResponses(t, s, cmd(serial.CmdSyncNextMessage))
	if resp[0][0] != serial.RespCodeChannelMsgRecv {
		t.Fatalf("expected ChannelMsgRecv, got %v", resp[0])
	}
	if resp[0][1] != 0 { // channel index (Public)
		t.Errorf("channel index = %d, want 0", resp[0][1])
	}
	if string(resp[0][8:]) != "hey" {
		t.Errorf("channel text = %q", resp[0][8:])
	}
}

func TestIncomingChannelUnknownDropped(t *testing.T) {
	var handler func(any)
	node := &fakeNode{clk: clock.New(), contacts: &stubStore{}}
	s := NewServer(Config{Node: node, Events: func(h func(any)) { handler = h }})

	badHash := crypto.ComputeChannelHash(crypto.DefaultChannelKey) + 1
	handler(&event.GroupTextReceived{Event: event.Event{}, ChannelHash: badHash, Message: "x"})

	resp := collectResponses(t, s, cmd(serial.CmdSyncNextMessage))
	if resp[0][0] != serial.RespCodeNoMoreMessages {
		t.Errorf("unknown-channel message should be dropped, got %v", resp[0])
	}
}

func TestNewAdvertPush(t *testing.T) {
	var handler func(any)
	node := &fakeNode{clk: clock.New(), contacts: &stubStore{}}
	s := NewServer(Config{Node: node, Events: func(h func(any)) { handler = h }})

	var out bytes.Buffer
	sess := &session{srv: s, w: &out, ctx: context.Background()}
	s.addSession(sess)

	var id core.MeshCoreID
	id[0], id[31] = 0x11, 0x22
	handler(&event.AdvertReceived{Contact: &contact.ContactInfo{ID: id, Name: "New", OutPathLen: 0xFF}, IsNew: true})

	frames := decodeFrames(&out)
	if len(frames) != 1 || frames[0][0] != serial.PushCodeNewAdvert || len(frames[0]) != 148 {
		t.Fatalf("expected 148-byte NewAdvert push, got %v", frames)
	}
	if !bytes.Equal(frames[0][1:33], id[:]) {
		t.Error("NewAdvert pubkey mismatch")
	}
}

func TestReheardAdvertPush(t *testing.T) {
	var handler func(any)
	node := &fakeNode{clk: clock.New(), contacts: &stubStore{}}
	s := NewServer(Config{Node: node, Events: func(h func(any)) { handler = h }})

	var out bytes.Buffer
	sess := &session{srv: s, w: &out, ctx: context.Background()}
	s.addSession(sess)

	var id core.MeshCoreID
	id[0] = 0xAB
	handler(&event.AdvertReceived{Contact: &contact.ContactInfo{ID: id, OutPathLen: 0xFF}, IsNew: false})

	frames := decodeFrames(&out)
	if len(frames) != 1 || frames[0][0] != serial.PushCodeAdvert || len(frames[0]) != 33 {
		t.Fatalf("expected 33-byte Advert push, got %v", frames)
	}
	if !bytes.Equal(frames[0][1:33], id[:]) {
		t.Error("Advert pubkey mismatch")
	}
}

func TestNotifyContactDeleted(t *testing.T) {
	node := &fakeNode{clk: clock.New(), contacts: &stubStore{}}
	s := NewServer(Config{Node: node})

	var out bytes.Buffer
	sess := &session{srv: s, w: &out, ctx: context.Background()}
	s.addSession(sess)

	var id core.MeshCoreID
	id[0] = 0x99
	s.NotifyContactDeleted(id)

	frames := decodeFrames(&out)
	if len(frames) != 1 || frames[0][0] != serial.PushCodeContactDeleted {
		t.Fatalf("expected ContactDeleted push, got %v", frames)
	}
	if !bytes.Equal(frames[0][1:33], id[:]) {
		t.Error("ContactDeleted pubkey mismatch")
	}
}
