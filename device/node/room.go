package node

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/ack"
	"github.com/kabili207/meshcore-go/device/advert"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/device/room"
	"github.com/kabili207/meshcore-go/device/router"
)

// RoomConfig configures a RoomNode.
type RoomConfig struct {
	// PrivateKey is the node's Ed25519 private key (64 bytes: seed + pubkey).
	PrivateKey ed25519.PrivateKey

	// Transports to connect to the mesh network.
	Transports []TransportOption

	// Router is an existing router to use. If nil, RoomNode creates its own.
	// Pre-creating a router is useful when other components need to reference
	// it before the node exists, for example a stats provider that reads
	// router counters or an observer wired via Router.SetPacketMonitor.
	Router *router.Router

	// Contacts is the contact store. Required.
	Contacts contact.ContactStore

	// Room is the room server configuration.
	Room room.ServerConfig

	// Advertisement
	Name     string   // Node name broadcast in adverts.
	NodeType uint8    // Default: codec.NodeTypeRoom.
	Lat      *float64 // Optional GPS latitude.
	Lon      *float64 // Optional GPS longitude.

	// AdvertLocalInterval is the local (zero-hop) advert interval in firmware
	// units (value * 2 minutes). Default: 1 (2 minutes).
	AdvertLocalInterval uint8

	// AdvertFloodInterval is the flood advert interval in hours. Default: 12.
	AdvertFloodInterval uint8

	// ACKTimeout is how long to wait for an ACK before retrying. Default: 12s.
	ACKTimeout time.Duration

	// MaxRetries is how many times to resend before giving up. Default: 3.
	MaxRetries int

	// ForwardPackets enables packet relaying. Default: true for room servers.
	ForwardPackets *bool

	// EventHandlers registered during construction.
	EventHandlers []event.Handler

	// Logger for node events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// RoomNode is a high-level room server node. It composes BaseNode with
// the room.Server for client/post management, ACK tracking, and
// advertisement scheduling.
type RoomNode struct {
	base        *BaseNode
	server      *room.Server
	ackTracker  *ack.Tracker
	advertSched *advert.Scheduler
	clk         *clock.Clock
	log         *slog.Logger
}

// NewRoom creates a RoomNode from the given configuration.
func NewRoom(cfg RoomConfig) (*RoomNode, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	nodeType := cfg.NodeType
	if nodeType == 0 {
		nodeType = codec.NodeTypeRoom
	}

	ackTimeout := cfg.ACKTimeout
	if ackTimeout == 0 {
		ackTimeout = 12 * time.Second
	}
	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}

	tracker := ack.NewTracker(ack.TrackerConfig{
		ACKTimeout: ackTimeout,
		MaxRetries: maxRetries,
		Logger:     logger,
	})

	clk := clock.New()

	// Default: room servers forward packets
	forwardPackets := true
	if cfg.ForwardPackets != nil {
		forwardPackets = *cfg.ForwardPackets
	}

	base, err := NewBase(BaseConfig{
		PrivateKey:     cfg.PrivateKey,
		Contacts:       cfg.Contacts,
		Clock:          clk,
		ACKTracker:     tracker,
		Router:         cfg.Router,
		Transports:     cfg.Transports,
		ForwardPackets: forwardPackets,
		EventHandlers:  cfg.EventHandlers,
		Logger:         logger,
	})
	if err != nil {
		return nil, fmt.Errorf("create base node: %w", err)
	}

	// Configure and create room server.
	// Fill in identity fields from our base node.
	roomCfg := cfg.Room
	roomCfg.PrivateKey = cfg.PrivateKey
	roomCfg.PublicKey = base.PublicKey()
	roomCfg.Clock = clk
	roomCfg.Contacts = cfg.Contacts
	roomCfg.ACKTracker = tracker
	roomCfg.Router = base.Router
	if roomCfg.Logger == nil {
		roomCfg.Logger = logger
	}

	srv := room.NewServer(roomCfg)
	srv.SetSender(base) // BaseNode implements room.NodeSender

	// Share the AppData pointer between the room server's CLI handlers and
	// the advert builder so that "set name/lat/lon" commands take effect on
	// subsequent advertisements. If the caller didn't supply AppData, fall
	// back to the RoomConfig fields.
	appData := roomCfg.AppData
	if appData == nil {
		appData = &codec.AdvertAppData{
			Name:     cfg.Name,
			NodeType: nodeType,
			Lat:      cfg.Lat,
			Lon:      cfg.Lon,
		}
	}

	advertBuilder := advert.NewSelfAdvertBuilder(&advert.SelfAdvertConfig{
		PrivateKey: cfg.PrivateKey,
		PublicKey:  base.PublicKey(),
		Clock:      clk,
		AppData:    appData,
	})

	localInterval := cfg.AdvertLocalInterval
	if localInterval == 0 {
		localInterval = advert.DefaultLocalAdvertInterval
	}
	floodInterval := cfg.AdvertFloodInterval
	if floodInterval == 0 {
		floodInterval = advert.DefaultFloodAdvertInterval
	}

	scheduler := advert.NewScheduler(base.Router, advertBuilder, advert.SchedulerConfig{
		LocalAdvertInterval: localInterval,
		FloodAdvertInterval: floodInterval,
		Logger:              logger,
	})

	n := &RoomNode{
		base:        base,
		server:      srv,
		ackTracker:  tracker,
		advertSched: scheduler,
		clk:         clk,
		log:         logger.WithGroup("room-node"),
	}

	// Wire events from BaseNode to room server handlers
	base.OnEvent(n.dispatchToServer)

	return n, nil
}

// dispatchToServer routes typed events to the room server's handler methods.
func (n *RoomNode) dispatchToServer(evt any) {
	switch e := evt.(type) {
	case *event.AnonRequestReceived:
		n.server.HandleLogin(e)
	case *event.TextMessageReceived:
		n.server.HandleTextMessage(e)
	case *event.RequestReceived:
		n.server.HandleRequest(e)
	case *event.PathReceived:
		n.server.HandlePath(e)
	case *event.AdvertReceived:
		n.server.HandleAdvertReceived(e)
	}
}

// Run starts all components and blocks until ctx is cancelled.
// Starts: transports, router, ACK tracker, room server sync loop, advert scheduler.
func (n *RoomNode) Run(ctx context.Context) error {
	if err := n.base.StartTransports(ctx); err != nil {
		return err
	}

	n.base.Router.Start(ctx)

	go n.ackTracker.Start(ctx)
	go n.server.Start(ctx)

	n.advertSched.SendNow(true)
	n.advertSched.Start(ctx)

	return nil
}

// OnEvent registers an event handler. Delegates to BaseNode.
func (n *RoomNode) OnEvent(fn event.Handler) {
	n.base.OnEvent(fn)
}

// Base returns the underlying BaseNode for advanced use.
func (n *RoomNode) Base() *BaseNode { return n.base }

// ID returns the node's MeshCoreID.
func (n *RoomNode) ID() core.MeshCoreID { return n.base.ID() }

// Server returns the underlying room.Server for direct access
// (e.g., setting CLI handlers, wiring persistence callbacks).
func (n *RoomNode) Server() *room.Server { return n.server }

// SetSendScope scopes this node's outbound flood traffic (responses, ACKs, path
// returns) to a region. Derive the key with router.TransportKeyFromRegion.
// Adverts and direct sends stay unscoped. Call ClearSendScope to revert.
func (n *RoomNode) SetSendScope(key router.TransportKey) {
	n.base.Router.SetSendScope(key)
}

// ClearSendScope reverts to unscoped flood sending.
func (n *RoomNode) ClearSendScope() {
	n.base.Router.ClearSendScope()
}

// AdvertScheduler returns the advert scheduler for manual control.
func (n *RoomNode) AdvertScheduler() *advert.Scheduler {
	return n.advertSched
}

// ACKTracker returns the ACK tracker.
func (n *RoomNode) ACKTracker() *ack.Tracker {
	return n.ackTracker
}
