package node

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/acl"
	"github.com/kabili207/meshcore-go/device/advert"
	"github.com/kabili207/meshcore-go/device/cli"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
)

// RepeaterConfig configures a RepeaterNode.
type RepeaterConfig struct {
	// PrivateKey is the node's Ed25519 private key (64 bytes: seed + pubkey).
	PrivateKey ed25519.PrivateKey

	// Transports to connect to the mesh network.
	Transports []TransportOption

	// Contacts is the contact store for neighbor tracking. If nil, a default
	// ContactManager is created.
	Contacts contact.ContactStore

	// AdminPassword grants admin access on login. Empty disables admin login.
	AdminPassword string

	// GuestPassword grants guest access on login. Empty disables guest login.
	GuestPassword string

	// MaxClients caps the ACL client table. Default: acl.DefaultMaxClients (20).
	MaxClients int

	// MaxNeighbors caps the directly-heard neighbor table. Default: 32.
	MaxNeighbors int

	// ACLPersistence, if set, makes the admin client list durable across restarts
	// (firmware persists admins to flash). See acl.NewFileStore.
	ACLPersistence acl.Persistence

	// Version is reported by the CLI "ver" command. Default: "meshcore-go".
	Version string

	// OnRegionsChanged, if set, persists the RegionMap after a "region" CLI edit.
	OnRegionsChanged func(data []byte) error

	// OnSettingChanged, if set, is called after a successful CLI "set".
	OnSettingChanged func(key, value string)

	// OnReboot, if set, is invoked by the "reboot" CLI command. The library never
	// restarts the process itself; the app decides what to do (restart, exit,
	// reconnect). Without it, "reboot" reports that it is unsupported.
	OnReboot func()

	// OnSetClock, if set, is invoked by the "time <epoch>" CLI command with the
	// requested epoch seconds. A transport-attached node usually carries a better
	// (host) clock than a remote client, so accepting a client's time is opt-in.
	// Return an error to report failure. Without it, "time" reports unsupported.
	OnSetClock func(epoch uint32) error

	// Advertisement
	Name string   // Node name broadcast in adverts.
	Lat  *float64 // Optional GPS latitude.
	Lon  *float64 // Optional GPS longitude.

	// AdvertLocalInterval is the local (zero-hop) advert interval in firmware
	// units (value * 2 minutes). Default: 1 (2 minutes).
	AdvertLocalInterval uint8

	// AdvertFloodInterval is the flood advert interval in hours. Default: 12.
	AdvertFloodInterval uint8

	// EventHandlers registered during construction.
	EventHandlers []event.Handler

	// Logger for node events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// RepeaterNode is a node for packet relaying with a remote admin surface. It
// forwards all packets, advertises its presence, tracks neighbors via advert
// processing, and authenticates admin/guest clients (ACL) for login.
type RepeaterNode struct {
	base            *BaseNode
	advertSched     *advert.Scheduler
	acl             *acl.MemoryStore
	auth            acl.Authenticator
	neighbors       *neighborTable
	discoverLimiter *rateLimiter
	cli             *cli.Dispatcher
	appData         *codec.AdvertAppData
	cfg             RepeaterConfig
	startTime       time.Time
	log             *slog.Logger

	discoverMu           sync.Mutex
	pendingDiscoverTag   uint32
	pendingDiscoverUntil time.Time
}

// NewRepeater creates a RepeaterNode from the given configuration.
func NewRepeater(cfg RepeaterConfig) (*RepeaterNode, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Repeaters don't need auto-ACK
	autoACK := false

	// Default contact store: needed for neighbor tracking and ACL login (a nil
	// store would panic on first use).
	contacts := cfg.Contacts
	if contacts == nil {
		contacts = contact.NewManager(cfg.PrivateKey, contact.ManagerConfig{
			MaxContacts:       256,
			OverwriteWhenFull: true,
		})
	}

	base, err := NewBase(BaseConfig{
		PrivateKey:     cfg.PrivateKey,
		Contacts:       contacts,
		Transports:     cfg.Transports,
		ForwardPackets: true, // always forward
		AutoACK:        &autoACK,
		EventHandlers:  cfg.EventHandlers,
		Logger:         logger,
	})
	if err != nil {
		return nil, fmt.Errorf("create base node: %w", err)
	}

	// Build advert scheduler. Keep the AppData pointer so CLI "set name/lat/lon"
	// takes effect on subsequent adverts.
	clk := base.Clock()
	appData := &codec.AdvertAppData{
		Name:     cfg.Name,
		NodeType: codec.NodeTypeRepeater,
		Lat:      cfg.Lat,
		Lon:      cfg.Lon,
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

	n := &RepeaterNode{
		base:        base,
		advertSched: scheduler,
		acl:         acl.NewMemoryStore(cfg.MaxClients, acl.WithPersistence(cfg.ACLPersistence)),
		auth: acl.Authenticator{
			// Repeater mapping: admin/guest passwords only, no open access.
			// A correct guest password grants GUEST (read-only-style access).
			AdminPassword: cfg.AdminPassword,
			GuestPassword: cfg.GuestPassword,
			GuestPerms:    codec.PermACLGuest,
		},
		neighbors: newNeighborTable(cfg.MaxNeighbors),
		// Firmware discover_limiter: max 4 responses every 2 minutes.
		discoverLimiter: newRateLimiter(4, 120),
		appData:         appData,
		cfg:             cfg,
		startTime:       time.Now(),
		log:             logger.WithGroup("repeater"),
	}
	n.cli = n.buildCLI()

	// Wire admin/ACL event handling (login, requests, CLI).
	base.OnEvent(n.dispatchEvents)

	return n, nil
}

// Run starts all components and blocks until ctx is cancelled.
// Starts: transports, router (with forwarding), advert scheduler.
func (n *RepeaterNode) Run(ctx context.Context) error {
	if err := n.base.StartTransports(ctx); err != nil {
		return err
	}

	n.base.Router.Start(ctx)

	n.advertSched.SendNow(true)
	n.advertSched.Start(ctx)

	return nil
}

// OnEvent registers an event handler. Delegates to BaseNode.
func (n *RepeaterNode) OnEvent(fn event.Handler) {
	n.base.OnEvent(fn)
}

// Base returns the underlying BaseNode for advanced use.
func (n *RepeaterNode) Base() *BaseNode { return n.base }

// ID returns the node's MeshCoreID.
func (n *RepeaterNode) ID() core.MeshCoreID { return n.base.ID() }

// AdvertScheduler returns the advert scheduler for manual control.
func (n *RepeaterNode) AdvertScheduler() *advert.Scheduler {
	return n.advertSched
}

// ACL returns the repeater's client access-control store.
func (n *RepeaterNode) ACL() *acl.MemoryStore {
	return n.acl
}
