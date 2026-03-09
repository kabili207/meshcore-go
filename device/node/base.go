// Package node provides high-level node abstractions for MeshCore networks.
//
// The BaseNode is the shared foundation for all node types. It owns the
// identity, router, transports, contact store, and event dispatch pipeline.
// Raw packets from the router are converted into typed events (defined in
// the event package) before being delivered to consumers.
//
// Node types (CompanionNode, RoomNode, RepeaterNode) compose BaseNode and
// add type-specific behavior.
package node

import (
	"crypto/ed25519"
	"log/slog"
	"sync"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/ack"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/device/router"
	"github.com/kabili207/meshcore-go/transport"
)

// TransportOption pairs a transport with its packet source identifier.
type TransportOption struct {
	Transport transport.Transport
	Source    transport.PacketSource
	Name      string // Human-readable name for events (e.g., "mqtt", "serial")
}

// BaseConfig contains configuration shared by all node types.
type BaseConfig struct {
	// PrivateKey is the node's Ed25519 private key (64 bytes: seed + pubkey).
	PrivateKey ed25519.PrivateKey

	// Contacts is the contact store for peer management.
	Contacts contact.ContactStore

	// Clock provides timestamps. If nil, a default clock is created.
	Clock *clock.Clock

	// ACKTracker tracks pending ACKs. If nil, ACK resolution events still
	// fire but no tracking/retry is performed.
	ACKTracker *ack.Tracker

	// Router is an existing router to use. If nil, a new router is created
	// from RouterConfig.
	Router *router.Router

	// RouterConfig is used to create a new router when Router is nil.
	RouterConfig router.Config

	// Transports to register with the router.
	Transports []TransportOption

	// ForwardPackets enables packet forwarding (repeater behavior).
	ForwardPackets bool

	// AutoACK controls whether the node automatically sends ACK packets
	// for received text messages. Default: true.
	AutoACK *bool

	// AutoUpdateContacts controls whether the node automatically updates
	// the contact store from valid ADVERTs. Default: true.
	AutoUpdateContacts *bool

	// EventHandlers are registered during construction (before Run).
	EventHandlers []event.Handler

	// Logger for node events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// BaseNode is the shared foundation for all node types. It handles the
// packet→event pipeline: decrypting, parsing, auto-ACK, contact updates,
// and typed event dispatch.
type BaseNode struct {
	// Identity
	privateKey ed25519.PrivateKey
	publicKey  [32]byte
	id         core.MeshCoreID

	// Core components
	Router   *router.Router
	contacts contact.ContactStore
	clock    *clock.Clock
	ack      *ack.Tracker

	// Configuration
	autoACK            bool
	autoUpdateContacts bool

	// Event system
	eventMu       sync.RWMutex
	eventHandlers []event.Handler

	log *slog.Logger
}

// NewBase creates a BaseNode from the given configuration. It does not start
// any background goroutines — call the owning node type's Run method for that.
func NewBase(cfg BaseConfig) (*BaseNode, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Derive public key and ID from private key
	var pubKey [32]byte
	copy(pubKey[:], cfg.PrivateKey.Public().(ed25519.PublicKey))
	var id core.MeshCoreID
	copy(id[:], pubKey[:])

	clk := cfg.Clock
	if clk == nil {
		clk = clock.New()
	}

	autoACK := true
	if cfg.AutoACK != nil {
		autoACK = *cfg.AutoACK
	}

	autoUpdate := true
	if cfg.AutoUpdateContacts != nil {
		autoUpdate = *cfg.AutoUpdateContacts
	}

	// Create or use provided router
	r := cfg.Router
	if r == nil {
		routerCfg := cfg.RouterConfig
		routerCfg.SelfID = id
		routerCfg.ForwardPackets = cfg.ForwardPackets
		if routerCfg.Logger == nil {
			routerCfg.Logger = logger
		}
		r = router.New(routerCfg)
	}

	b := &BaseNode{
		privateKey:         cfg.PrivateKey,
		publicKey:          pubKey,
		id:                 id,
		Router:             r,
		contacts:           cfg.Contacts,
		clock:              clk,
		ack:                cfg.ACKTracker,
		autoACK:            autoACK,
		autoUpdateContacts: autoUpdate,
		log:                logger.WithGroup("node"),
	}

	// Register event handlers from config
	for _, h := range cfg.EventHandlers {
		b.eventHandlers = append(b.eventHandlers, h)
	}

	// Register transports
	for _, t := range cfg.Transports {
		r.AddTransport(t.Transport, t.Source)

		// Wire transport state changes to events
		name := t.Name
		t.Transport.SetStateHandler(func(_ transport.Transport, evt transport.Event) {
			b.emitEvent(&event.TransportStateChanged{
				TransportName: name,
				State:         evt,
			})
		})
	}

	// Wire the router's packet handler to our dispatch pipeline
	r.SetPacketHandler(b.processPacket)

	return b, nil
}

// ID returns the node's MeshCoreID.
func (b *BaseNode) ID() core.MeshCoreID { return b.id }

// PublicKey returns the node's 32-byte Ed25519 public key.
func (b *BaseNode) PublicKey() [32]byte { return b.publicKey }

// PrivateKey returns the node's Ed25519 private key.
func (b *BaseNode) PrivateKey() ed25519.PrivateKey { return b.privateKey }

// Contacts returns the contact store.
func (b *BaseNode) Contacts() contact.ContactStore { return b.contacts }

// Clock returns the node's clock.
func (b *BaseNode) Clock() *clock.Clock { return b.clock }

// OnEvent registers an event handler. Handlers are called synchronously
// in the order they were registered. Safe to call from multiple goroutines.
func (b *BaseNode) OnEvent(fn event.Handler) {
	b.eventMu.Lock()
	defer b.eventMu.Unlock()
	b.eventHandlers = append(b.eventHandlers, fn)
}

// emitEvent dispatches an event to all registered handlers.
func (b *BaseNode) emitEvent(evt any) {
	b.eventMu.RLock()
	handlers := b.eventHandlers
	b.eventMu.RUnlock()
	for _, fn := range handlers {
		fn(evt)
	}
}

// SendReply sends an encrypted response using a ReplyContext from a received
// event. Automatically chooses the routing strategy:
//   - If the original packet was flood-routed: wraps response in PATH packet
//   - If a direct path is known: sends via direct routing
//   - Otherwise: sends via flood
func (b *BaseNode) SendReply(reply event.ReplyContext, to core.MeshCoreID, payloadType uint8, plaintext []byte) error {
	if reply.HasFloodPath() {
		return b.sendPathReturn(reply, to, payloadType, plaintext)
	}
	return b.sendEncryptedResponse(reply, to, payloadType, plaintext)
}

// sendEncryptedResponse encrypts and sends a response as an addressed packet.
func (b *BaseNode) sendEncryptedResponse(reply event.ReplyContext, to core.MeshCoreID, payloadType uint8, plaintext []byte) error {
	encrypted, err := crypto.EncryptAddressedWithSecret(plaintext, reply.SharedSecret)
	if err != nil {
		return err
	}

	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildAddressedPayload(to.Hash(), b.id.Hash(), mac, ciphertext)
	pkt := codec.NewPacket(payloadType, codec.RouteTypeFlood, payload)

	if reply.HasDirectPath() {
		b.Router.SendDirect(pkt, reply.DirectPath[:reply.DirectPathLen])
	} else {
		b.Router.SendFlood(pkt)
	}
	return nil
}

// sendPathReturn wraps a response in a PATH packet with the reversed flood
// path, matching firmware's createPathReturn() behavior.
func (b *BaseNode) sendPathReturn(reply event.ReplyContext, to core.MeshCoreID, extraType uint8, plaintext []byte) error {
	pathContent := codec.BuildPathContent(reply.FloodPath, extraType, plaintext)

	encrypted, err := crypto.EncryptAddressedWithSecret(pathContent, reply.SharedSecret)
	if err != nil {
		return err
	}

	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildAddressedPayload(to.Hash(), b.id.Hash(), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypePath, codec.RouteTypeFlood, payload)

	b.Router.SendFloodPath(pkt)
	return nil
}

// sendACK sends an ACK packet to the recipient.
func (b *BaseNode) sendACK(to core.MeshCoreID, ackHash uint32) {
	pkt := codec.NewPacket(codec.PayloadTypeAck, codec.RouteTypeFlood, codec.BuildAckPayload(ackHash))

	ct := b.contacts.GetByPubKey(to)
	if ct != nil && ct.HasDirectPath() {
		b.Router.SendDirect(pkt, ct.OutPath[:ct.OutPathLen])
	} else {
		b.Router.SendFlood(pkt)
	}
}

// buildReplyContext constructs a ReplyContext from a decrypted addressed packet.
func (b *BaseNode) buildReplyContext(pkt *codec.Packet, ct *contact.ContactInfo, secret []byte) event.ReplyContext {
	reply := event.ReplyContext{
		SharedSecret:  secret,
		DirectPathLen: ct.OutPathLen,
	}
	if ct.HasDirectPath() {
		reply.DirectPath = make([]byte, ct.OutPathLen)
		copy(reply.DirectPath, ct.OutPath[:ct.OutPathLen])
	}
	if pkt.IsFlood() && pkt.PathLen > 0 {
		reply.FloodPath = codec.ReverseFloodPath(pkt)
	}
	return reply
}

// updateContactPathFromFlood updates a contact's direct path from an incoming
// flood packet by reversing the flood path.
func (b *BaseNode) updateContactPathFromFlood(pkt *codec.Packet, ct *contact.ContactInfo) {
	if !pkt.IsFlood() || pkt.PathLen == 0 {
		return
	}
	reversed := codec.ReverseFloodPath(pkt)
	ct.OutPathLen = int8(len(reversed))
	ct.OutPath = reversed
	ct.LastMod = b.clock.GetCurrentTime()
}
