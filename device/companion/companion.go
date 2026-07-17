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
// Phase 1 implements the connect milestone: APP_START -> SELF_INFO,
// DEVICE_QUERY -> DEVICE_INFO, GET_CONTACTS streaming, and device time.
// Unimplemented commands return RESP_CODE_ERR so the app degrades gracefully.
// Messaging and channels arrive in later phases.
package companion

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"sync"

	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec/serial"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
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
	// Logger for connection events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// Server serves the companion protocol for one Node over accepted connections.
type Server struct {
	node Node
	id   Identity
	log  *slog.Logger

	mu   sync.RWMutex // guards mutable identity fields
	name string       // current advertised name; SET_ADVERT_NAME updates it
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
	return &Server{node: cfg.Node, id: id, log: log.WithGroup("companion"), name: id.Name}
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
	sess := &session{srv: s, w: rw}
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
// DEVICE_QUERY and selects the incoming-message layout in later phases.
type session struct {
	srv          *Server
	w            io.Writer
	mu           sync.Mutex // serializes frame writes (loop replies and, later, pushes)
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

	case serial.CmdGetChannel:
		return s.sendChannel(ss, payload)

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
		// No offline message queue yet (phase 2); report the queue empty.
		return ss.send(serial.EncodeNoMoreMessages())

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

// sendChannel answers CMD_GET_CHANNEL. Index 0 is the built-in Public channel;
// other in-range indices report as empty (unconfigured); out-of-range indices
// return NotFound, matching the firmware.
func (s *Server) sendChannel(ss *session, payload []byte) error {
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
