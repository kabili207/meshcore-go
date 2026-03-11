package node

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/advert"
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

	// Advertisement
	Name     string   // Node name broadcast in adverts.
	Lat      *float64 // Optional GPS latitude.
	Lon      *float64 // Optional GPS longitude.

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

// RepeaterNode is a minimal node for packet relaying. It forwards all
// packets, advertises its presence, and tracks neighbors via advert
// processing. No text message handling, ACK tracking, or keep-alive.
type RepeaterNode struct {
	base        *BaseNode
	advertSched *advert.Scheduler
	log         *slog.Logger
}

// NewRepeater creates a RepeaterNode from the given configuration.
func NewRepeater(cfg RepeaterConfig) (*RepeaterNode, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Repeaters don't need auto-ACK
	autoACK := false

	base, err := NewBase(BaseConfig{
		PrivateKey:     cfg.PrivateKey,
		Contacts:       cfg.Contacts,
		Transports:     cfg.Transports,
		ForwardPackets: true, // always forward
		AutoACK:        &autoACK,
		EventHandlers:  cfg.EventHandlers,
		Logger:         logger,
	})
	if err != nil {
		return nil, fmt.Errorf("create base node: %w", err)
	}

	// Build advert scheduler
	clk := base.Clock()
	advertBuilder := advert.NewSelfAdvertBuilder(&advert.SelfAdvertConfig{
		PrivateKey: cfg.PrivateKey,
		PublicKey:  base.PublicKey(),
		Clock:      clk,
		AppData: &codec.AdvertAppData{
			Name:     cfg.Name,
			NodeType: codec.NodeTypeRepeater,
			Lat:      cfg.Lat,
			Lon:      cfg.Lon,
		},
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

	return &RepeaterNode{
		base:        base,
		advertSched: scheduler,
		log:         logger.WithGroup("repeater"),
	}, nil
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
