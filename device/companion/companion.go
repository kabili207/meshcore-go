// Package companion serves the MeshCore companion protocol to a host app (a
// phone app, or MeshMonitor via @liamcottle/meshcore.js) over a byte stream. It
// makes a meshcore-go node present itself as a companion device that the app
// connects to and drives: it answers the handshake, streams contacts, and (in
// later phases) relays messages.
//
// The wire framing and payload codecs live in core/codec/serial. This package
// is the stateful server: it accepts a connection, reads command frames,
// dispatches them, and writes response/push frames. The framing is identical on
// serial and TCP, so ListenAndServe (TCP) and Serve (any stream, e.g. a pty)
// share one dispatch path.
//
// Implemented so far: the connect handshake (APP_START -> SELF_INFO,
// DEVICE_QUERY -> DEVICE_INFO), GET_CONTACTS streaming, device time,
// battery/storage, channel reads, flood-scope and advert-name config, and
// messaging: direct (SEND_TXT_MSG with SENT/SEND_CONFIRMED) and channel
// (SEND_CHANNEL_TXT_MSG), plus incoming DMs and group messages via the
// MSG_WAITING -> SYNC_NEXT_MESSAGE queue. The remote repeater login/CLI gateway
// is not yet wired. Unimplemented commands return RESP_CODE_ERR so the app
// degrades gracefully.
package companion

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec/serial"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
)

// Node is the subset of a meshcore-go node the companion server reads. A
// *node.BaseNode satisfies it, so callers pass companionNode.Base(). Later
// phases will extend this with send methods.
type Node interface {
	PublicKey() [32]byte
	Contacts() contact.ContactStore
	Clock() *clock.Clock
}

// Identity is the static device description the server reports in SELF_INFO and
// DEVICE_INFO. The public key comes from the Node; everything the node does not
// model (radio params, firmware strings) is supplied here.
type Identity struct {
	Name       string
	AdvType    uint8 // advertised role: 1 chat (default), 2 repeater, 3 room
	TxPower    uint8
	MaxTxPower uint8
	Lat, Lon   float64 // degrees; sent as fixed-point x1e6

	RadioFreqMHz float64 // e.g. 915.0
	RadioBWkHz   float64 // e.g. 250
	RadioSF      uint8
	RadioCR      uint8

	FirmwareVerCode  uint8  // protocol/firmware version code; default 13 (v1.16.0)
	FirmwareVersion  string // default "v1.16.0"
	BuildDate        string // firmware build date; default "6 Jun 2026"
	Manufacturer     string // model/manufacturer string; default "meshcore-go"
	MaxContacts      int    // default 256
	MaxGroupChannels uint8  // default 8

	// BatteryMilliVolts is reported in GET_BATT_AND_STORAGE; default 4200.
	// StorageUsedKB / StorageTotalKB report flash usage (default 0, no storage).
	BatteryMilliVolts uint16
	StorageUsedKB     uint32
	StorageTotalKB    uint32
}

// Config configures a Server.
type Config struct {
	// Node supplies identity, contacts, and clock. Required.
	Node Node
	// Identity describes the device to report to the app.
	Identity Identity

	// Events, if set, is invoked once during NewServer with the server's event
	// handler; wire it to the node's OnEvent so incoming messages are delivered
	// to connected apps. Without it, no incoming messages are queued.
	Events func(handler func(evt any))

	// SendDM, if set, sends a direct text message to a contact. It returns
	// whether the message went via flood (no known direct path) and invokes
	// onAck when the recipient acknowledges. Without it, CMD_SEND_TXT_MSG
	// returns an error.
	SendDM func(ctx context.Context, to core.MeshCoreID, text string, txtType, attempt uint8, onAck func()) (flood bool, err error)

	// SendChannel, if set, sends a text message to a group channel by index
	// (index 0 is the built-in Public channel). Without it,
	// CMD_SEND_CHANNEL_TXT_MSG returns an error.
	SendChannel func(ctx context.Context, channelIdx uint8, text string) error

	// Logger for connection events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// Server serves the companion protocol for one Node over accepted connections.
type Server struct {
	node        Node
	id          Identity
	sendDM      func(ctx context.Context, to core.MeshCoreID, text string, txtType, attempt uint8, onAck func()) (bool, error)
	sendChannel func(ctx context.Context, channelIdx uint8, text string) error
	pubChanHash uint8 // channel hash of the built-in Public channel
	log         *slog.Logger

	mu   sync.RWMutex // guards mutable identity fields
	name string       // current advertised name; SET_ADVERT_NAME updates it

	ackCounter atomic.Uint32 // per-send correlation token for SENT/SEND_CONFIRMED

	msgMu    sync.Mutex            // guards queue and sessions
	queue    []queuedMessage       // offline incoming-message queue
	sessions map[*session]struct{} // currently connected apps
}

// queuedMessage is an incoming message awaiting CMD_SYNC_NEXT_MESSAGE drain. It
// is either a direct message (senderPrefix set) or a channel message (isChannel
// with channelIdx set).
type queuedMessage struct {
	isChannel    bool
	senderPrefix [6]byte
	channelIdx   uint8
	pathLen      uint8
	txtType      uint8
	senderTS     uint32
	snr          int8
	text         string
}

// NewServer builds a Server, filling in Identity defaults. It panics if
// cfg.Node is nil.
func NewServer(cfg Config) *Server {
	if cfg.Node == nil {
		panic("companion: Config.Node is required")
	}
	id := cfg.Identity
	if id.AdvType == 0 {
		id.AdvType = serial.AdvTypeChat
	}
	if id.FirmwareVerCode == 0 {
		id.FirmwareVerCode = serial.CompanionFirmwareVerCode
	}
	if id.FirmwareVersion == "" {
		id.FirmwareVersion = "v1.16.0"
	}
	if id.BuildDate == "" {
		id.BuildDate = "6 Jun 2026"
	}
	if id.Manufacturer == "" {
		id.Manufacturer = "meshcore-go"
	}
	if id.MaxContacts == 0 {
		id.MaxContacts = 256
	}
	if id.MaxGroupChannels == 0 {
		id.MaxGroupChannels = 8
	}
	if id.BatteryMilliVolts == 0 {
		id.BatteryMilliVolts = 4200
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		node:        cfg.Node,
		id:          id,
		sendDM:      cfg.SendDM,
		sendChannel: cfg.SendChannel,
		pubChanHash: crypto.ComputeChannelHash(crypto.DefaultChannelKey),
		log:         log.WithGroup("companion"),
		name:        id.Name,
		sessions:    make(map[*session]struct{}),
	}
	if cfg.Events != nil {
		cfg.Events(s.handleEvent)
	}
	return s
}

// ListenAndServe accepts TCP connections on addr and serves each. MeshMonitor's
// MeshCore backend connects to companion devices over TCP unmodified, so this
// is the primary entry point. It blocks until ctx is cancelled (which closes
// the listener and open connections) or Accept fails.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	s.log.Info("companion server listening", "addr", ln.Addr().String())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go func() {
			defer conn.Close()
			stop := make(chan struct{})
			defer close(stop)
			go func() {
				select {
				case <-ctx.Done():
					conn.Close()
				case <-stop:
				}
			}()
			if err := s.Serve(ctx, conn); err != nil && ctx.Err() == nil {
				s.log.Debug("companion connection ended", "error", err)
			}
		}()
	}
}

// Serve runs the companion protocol over rw until the stream closes or ctx is
// cancelled. Use it directly to serve a pty (the serial path) instead of TCP.
func (s *Server) Serve(ctx context.Context, rw io.ReadWriter) error {
	sess := &session{srv: s, w: rw, ctx: ctx}
	s.addSession(sess)
	defer s.removeSession(sess)

	fr := serial.NewFrameReader(rw)
	for {
		marker, payload, err := fr.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		// Ignore device-marked frames from the app side; only commands are valid.
		if marker != serial.FrameAppToNode || len(payload) == 0 {
			continue
		}
		if err := s.dispatch(sess, payload); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

// session is the per-connection state. appTargetVer is negotiated by
// DEVICE_QUERY and selects the incoming-message layout (V3 vs pre-V3).
type session struct {
	srv          *Server
	w            io.Writer
	ctx          context.Context
	mu           sync.Mutex // serializes frame writes (loop replies and async pushes)
	appTargetVer uint8
}

// send frames a payload as a device->app frame and writes it.
func (ss *session) send(payload []byte) error {
	frame, err := serial.EncodeFrame(serial.FrameNodeToApp, payload)
	if err != nil {
		return err
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	_, err = ss.w.Write(frame)
	return err
}

// dispatch routes one command frame to its handler.
func (s *Server) dispatch(ss *session, payload []byte) error {
	switch payload[0] {
	case serial.CmdAppStart:
		if name, err := serial.ParseAppStart(payload); err == nil {
			s.log.Info("app connected", "name", name)
		}
		return ss.send(s.selfInfo())

	case serial.CmdDeviceQuery:
		if ver, err := serial.ParseDeviceQuery(payload); err == nil {
			ss.appTargetVer = ver
		}
		return ss.send(s.deviceInfo())

	case serial.CmdGetContacts:
		return s.sendContacts(ss, payload)

	case serial.CmdSendTxtMsg:
		return s.sendTextMsg(ss, payload)

	case serial.CmdSendChannelTxtMsg:
		return s.sendChannelMsg(ss, payload)

	case serial.CmdGetChannel:
		return s.getChannel(ss, payload)

	case serial.CmdGetDeviceTime:
		return ss.send(serial.EncodeCurrTime(s.node.Clock().GetCurrentTime()))

	case serial.CmdSetDeviceTime:
		// A transport-attached node keeps its own (host) clock; acknowledge the
		// app's set without overriding it.
		return ss.send(serial.EncodeOK())

	case serial.CmdGetBattAndStorage:
		return ss.send(serial.EncodeBattAndStorage(
			s.id.BatteryMilliVolts, s.id.StorageUsedKB, s.id.StorageTotalKB))

	case serial.CmdGetDefaultFloodScope:
		// No default flood scope configured; report unset.
		return ss.send(serial.EncodeDefaultFloodScope("", nil))

	case serial.CmdSyncNextMessage:
		return s.sendNextMessage(ss)

	case serial.CmdSetAdvertName:
		if name, err := serial.ParseSetAdvertName(payload); err == nil {
			s.setName(name)
			s.log.Info("advert name set", "name", name)
		}
		return ss.send(serial.EncodeOK())

	case serial.CmdSendSelfAdvert:
		// The node's own scheduler advertises on its interval; acknowledge.
		return ss.send(serial.EncodeOK())

	case serial.CmdSetAdvertLatLon, serial.CmdSetOtherParams,
		serial.CmdSetFloodScopeKey, serial.CmdSetDefaultFloodScope:
		// Device-parameter writes we accept but do not persist on a virtual node.
		return ss.send(serial.EncodeOK())

	default:
		// Log the opcode so a real client's command sequence reveals what to
		// implement next. ErrCodeUnsupportedCmd (1) matches the firmware's
		// UNSUPPORTED_CMD wire value.
		s.log.Debug("unsupported command", "cmd", payload[0])
		return ss.send(serial.EncodeErr(serial.ErrCodeUnsupportedCmd))
	}
}

// selfInfo builds the SELF_INFO reply from the node's key and configured identity.
func (s *Server) selfInfo() []byte {
	si := &serial.SelfInfo{
		AdvType:    s.id.AdvType,
		TxPower:    s.id.TxPower,
		MaxTxPower: s.id.MaxTxPower,
		PublicKey:  s.node.PublicKey(),
		AdvLat:     degToFixed(s.id.Lat),
		AdvLon:     degToFixed(s.id.Lon),
		RadioFreq:  uint32(math.Round(s.id.RadioFreqMHz * 1000)), // MHz -> kHz
		RadioBw:    uint32(math.Round(s.id.RadioBWkHz * 1000)),   // kHz -> Hz
		RadioSf:    s.id.RadioSF,
		RadioCr:    s.id.RadioCR,
		Name:       s.currentName(),
	}
	return si.Encode()
}

// currentName returns the node's advertised name, which SET_ADVERT_NAME may have
// updated since construction.
func (s *Server) currentName() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.name
}

// setName updates the advertised name reported in subsequent SELF_INFO replies.
func (s *Server) setName(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.name = name
}

// getChannel answers CMD_GET_CHANNEL. Index 0 is the built-in Public channel;
// other in-range indices report as empty (unconfigured); out-of-range indices
// return NotFound, matching the firmware.
func (s *Server) getChannel(ss *session, payload []byte) error {
	idx, err := serial.ParseGetChannel(payload)
	if err != nil {
		return ss.send(serial.EncodeErr(serial.ErrCodeIllegalArg))
	}
	if uint16(idx) >= uint16(s.id.MaxGroupChannels) {
		return ss.send(serial.EncodeErr(serial.ErrCodeNotFound))
	}
	ci := &serial.ChannelInfo{Index: idx}
	if idx == 0 {
		ci.Name = "Public"
		ci.Secret = crypto.DefaultChannelKey
	}
	return ss.send(ci.Encode())
}

// sendTextMsg handles CMD_SEND_TXT_MSG: resolve the recipient, send the message
// through the node, reply RESP_CODE_SENT, and push PUSH_CODE_SEND_CONFIRMED when
// the recipient acknowledges.
func (s *Server) sendTextMsg(ss *session, payload []byte) error {
	if s.sendDM == nil {
		return ss.send(serial.EncodeErr(serial.ErrCodeUnsupportedCmd))
	}
	req, err := serial.ParseSendTxtMsg(payload)
	if err != nil {
		return ss.send(serial.EncodeErr(serial.ErrCodeIllegalArg))
	}
	ct := s.resolveContact(req.DestPrefix)
	if ct == nil {
		return ss.send(serial.EncodeErr(serial.ErrCodeNotFound))
	}

	// The app correlates its RESP_CODE_SENT.expected_ack with the later
	// PUSH_CODE_SEND_CONFIRMED.ack_code; a server-side token keeps that pairing
	// unique regardless of the on-air ACK CRC.
	token := s.ackCounter.Add(1)
	start := time.Now()
	flood, err := s.sendDM(ss.ctx, ct.ID, req.Text, req.TxtType, req.Attempt, func() {
		rtt := uint32(time.Since(start).Milliseconds())
		_ = ss.send(serial.EncodeSendConfirmed(token, rtt))
	})
	if err != nil {
		s.log.Warn("send failed", "to", ct.ID.String(), "error", err)
		return ss.send(serial.EncodeErr(serial.ErrCodeTableFull))
	}

	sentType := uint8(serial.SentTypeDirect)
	estTimeout := uint32(4000)
	if flood {
		sentType = serial.SentTypeFlood
		estTimeout = 8000
	}
	return ss.send(serial.EncodeSent(sentType, token, estTimeout))
}

// sendChannelMsg handles CMD_SEND_CHANNEL_TXT_MSG. Unlike a direct message, the
// firmware replies with RESP_CODE_OK (not RESP_CODE_SENT) and there is no
// delivery confirmation: group messages are unacknowledged broadcasts.
func (s *Server) sendChannelMsg(ss *session, payload []byte) error {
	if s.sendChannel == nil {
		return ss.send(serial.EncodeErr(serial.ErrCodeUnsupportedCmd))
	}
	req, err := serial.ParseSendChannelTxtMsg(payload)
	if err != nil {
		return ss.send(serial.EncodeErr(serial.ErrCodeIllegalArg))
	}
	if req.TxtType != 0 { // firmware only accepts TXT_TYPE_PLAIN on a channel
		return ss.send(serial.EncodeErr(serial.ErrCodeUnsupportedCmd))
	}
	if err := s.sendChannel(ss.ctx, req.ChannelIdx, req.Text); err != nil {
		s.log.Warn("channel send failed", "channel", req.ChannelIdx, "error", err)
		return ss.send(serial.EncodeErr(serial.ErrCodeNotFound))
	}
	return ss.send(serial.EncodeOK())
}

// resolveContact finds the stored contact whose public key starts with prefix
// (the 6-byte prefix the app sends), or nil if none match.
func (s *Server) resolveContact(prefix []byte) *contact.ContactInfo {
	var found *contact.ContactInfo
	s.node.Contacts().ForEach(func(c *contact.ContactInfo) bool {
		if bytes.HasPrefix(c.ID[:], prefix) {
			found = c
			return false
		}
		return true
	})
	return found
}

// sendNextMessage drains one queued incoming message, encoded for the session's
// negotiated protocol version, or reports the queue empty.
func (s *Server) sendNextMessage(ss *session) error {
	s.msgMu.Lock()
	if len(s.queue) == 0 {
		s.msgMu.Unlock()
		return ss.send(serial.EncodeNoMoreMessages())
	}
	qm := s.queue[0]
	s.queue = s.queue[1:]
	s.msgMu.Unlock()

	v3 := ss.appTargetVer >= 3
	var frame []byte
	if qm.isChannel {
		frame = serial.EncodeChannelMsgRecv(v3, qm.snr, qm.channelIdx, qm.pathLen, qm.txtType, qm.senderTS, qm.text)
	} else {
		frame = serial.EncodeContactMsgRecv(v3, qm.snr, qm.senderPrefix[:], qm.pathLen, qm.txtType, qm.senderTS, qm.text)
	}
	return ss.send(frame)
}

// handleEvent receives node events, queuing incoming messages and pushing live
// contact updates to connected apps.
func (s *Server) handleEvent(evt any) {
	switch e := evt.(type) {
	case *event.TextMessageReceived:
		s.enqueueDM(e)
	case *event.GroupTextReceived:
		s.enqueueChannel(e)
	case *event.AdvertReceived:
		s.pushAdvert(e)
	}
}

// pushAdvert emits NEW_ADVERT for a first-seen contact (the full contact frame)
// or ADVERT for a re-heard one (pubkey only), so the app's contact list updates
// live without a manual refresh.
func (s *Server) pushAdvert(e *event.AdvertReceived) {
	if e.Contact == nil {
		return
	}
	if e.IsNew {
		s.pushToSessions(contactToWire(e.Contact).EncodeWithCode(serial.PushCodeNewAdvert))
	} else {
		s.pushToSessions(serial.EncodeAdvert([32]byte(e.Contact.ID)))
	}
}

// NotifyContactDeleted emits PUSH_CODE_CONTACT_DELETED. Wire it to the contact
// store's overwrite/removal callback (e.g. ContactManager.SetOnContactOverwrite).
func (s *Server) NotifyContactDeleted(id core.MeshCoreID) {
	s.pushToSessions(serial.EncodeContactDeleted([32]byte(id)))
}

// NotifyPathUpdated emits PUSH_CODE_PATH_UPDATED for a contact whose route
// changed. meshcore-go has no dedicated path-changed signal, so wire this from
// your own if you have one.
func (s *Server) NotifyPathUpdated(id core.MeshCoreID) {
	s.pushToSessions(serial.EncodePathUpdated([32]byte(id)))
}

// NotifyContactsFull emits PUSH_CODE_CONTACTS_FULL when the contact table is full.
func (s *Server) NotifyContactsFull() {
	s.pushToSessions(serial.EncodeContactsFull())
}

// enqueueDM queues an incoming direct message and tickles connected apps.
func (s *Server) enqueueDM(e *event.TextMessageReceived) {
	qm := queuedMessage{
		pathLen:  serial.PathLenUnknown, // direct/unknown; refined when packet path is exposed
		txtType:  e.TxtType,
		senderTS: e.Timestamp,
		text:     e.Message,
	}
	copy(qm.senderPrefix[:], e.From[:])
	s.enqueue(qm)
}

// enqueueChannel queues an incoming group message. Only channels the server can
// map to an index (currently the built-in Public channel) are delivered.
func (s *Server) enqueueChannel(e *event.GroupTextReceived) {
	if e.ChannelHash != s.pubChanHash {
		s.log.Debug("dropping message for unknown channel", "hash", e.ChannelHash)
		return
	}
	s.enqueue(queuedMessage{
		isChannel:  true,
		channelIdx: 0, // Public
		pathLen:    serial.PathLenUnknown,
		txtType:    0, // plain
		senderTS:   s.node.Clock().GetCurrentTime(),
		text:       e.Message,
	})
}

// enqueue appends a message to the offline queue and tickles connected apps.
func (s *Server) enqueue(qm queuedMessage) {
	s.msgMu.Lock()
	s.queue = append(s.queue, qm)
	s.msgMu.Unlock()
	s.pushToSessions(serial.EncodeMsgWaiting())
}

// pushToSessions writes an unsolicited push frame to every connected app. Apps
// that are not connected simply miss it, matching the firmware.
func (s *Server) pushToSessions(payload []byte) {
	s.msgMu.Lock()
	sessions := make([]*session, 0, len(s.sessions))
	for sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.msgMu.Unlock()

	for _, sess := range sessions {
		if err := sess.send(payload); err != nil {
			s.log.Debug("push failed", "error", err)
		}
	}
}

func (s *Server) addSession(sess *session) {
	s.msgMu.Lock()
	s.sessions[sess] = struct{}{}
	s.msgMu.Unlock()
}

func (s *Server) removeSession(sess *session) {
	s.msgMu.Lock()
	delete(s.sessions, sess)
	s.msgMu.Unlock()
}

// deviceInfo builds the DEVICE_INFO reply.
func (s *Server) deviceInfo() []byte {
	di := &serial.DeviceInfo{
		FirmwareVerCode:  s.id.FirmwareVerCode,
		MaxContactsDiv2:  uint8(s.id.MaxContacts / 2),
		MaxGroupChannels: s.id.MaxGroupChannels,
		BuildDate:        s.id.BuildDate,
		Manufacturer:     s.id.Manufacturer,
		FirmwareVersion:  s.id.FirmwareVersion,
	}
	return di.Encode()
}

// sendContacts streams ContactsStart -> Contact* -> EndOfContacts, honoring the
// optional "since" filter (only contacts modified after it).
func (s *Server) sendContacts(ss *session, payload []byte) error {
	since, hasSince := serial.ParseGetContactsSince(payload)

	var matched []*contact.ContactInfo
	var mostRecent uint32
	s.node.Contacts().ForEach(func(c *contact.ContactInfo) bool {
		if c.LastMod > mostRecent {
			mostRecent = c.LastMod
		}
		if hasSince && c.LastMod <= since {
			return true
		}
		matched = append(matched, c)
		return true
	})

	// Count is the number of Contact frames that follow; the client terminates
	// on EndOfContacts regardless (matching real-firmware incremental sync).
	if err := ss.send(serial.EncodeContactsStart(uint32(len(matched)))); err != nil {
		return err
	}
	for _, c := range matched {
		if err := ss.send(contactToWire(c).Encode()); err != nil {
			return err
		}
	}
	return ss.send(serial.EncodeEndOfContacts(mostRecent))
}

// contactToWire maps a stored contact to the companion Contact frame.
func contactToWire(c *contact.ContactInfo) *serial.Contact {
	wc := &serial.Contact{
		Type:       c.Type,
		Flags:      c.Flags,
		OutPathLen: c.OutPathLen,
		OutPath:    c.OutPath,
		Name:       c.Name,
		LastAdvert: c.LastAdvertTimestamp,
		GPSLat:     c.GPSLat,
		GPSLon:     c.GPSLon,
		LastMod:    c.LastMod,
	}
	copy(wc.PublicKey[:], c.ID[:])
	return wc
}

// degToFixed converts degrees to the firmware's fixed-point degrees x1e6.
func degToFixed(deg float64) int32 {
	return int32(math.Round(deg * 1e6))
}
