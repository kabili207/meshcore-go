// Package room provides a MeshCore room server implementation.
//
// A room server manages connected clients, stores messages (posts), and
// synchronizes posts to clients via a push-based sync loop. This corresponds
// to the firmware's RoomMesh / MyMesh implementation.
//
// The server uses pluggable storage interfaces (ClientStore, PostStore) and
// the contact.ContactStore for peer tracking, allowing alternative backends.
package room

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"sync"

	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/ack"
	"github.com/kabili207/meshcore-go/device/cli"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/router"
)

// ServerConfig configures a room Server.
type ServerConfig struct {
	// Identity
	PrivateKey ed25519.PrivateKey
	PublicKey  [32]byte

	// Clock for timestamps
	Clock *clock.Clock

	// AdminPassword is the password granting PermACLAdmin access.
	// If empty, admin access requires being in the client store already.
	AdminPassword string

	// GuestPassword is the password granting PermACLReadWrite access.
	// If empty, guest login falls back to ReadOnly (if AllowReadOnly is true).
	GuestPassword string

	// AllowReadOnly grants PermACLReadOnly to clients that don't provide
	// a matching password (open room).
	AllowReadOnly bool

	// Storage backends
	Clients  ClientStore
	Posts    PostStore
	Contacts contact.ContactStore

	// Network
	Router     *router.Router
	ACKTracker *ack.Tracker

	// Optional providers for REQ responses. If nil, the corresponding
	// request type returns no response (same as firmware when hardware
	// is unavailable).
	Stats     StatsProvider
	Telemetry TelemetryProvider

	// PostCounter is an optional counter for room-level post statistics.
	// DefaultStatsProvider implements this interface.
	PostCounter PostCounter

	// Name is the server's display name, returned by the "get name" CLI command.
	Name string

	// Version is the version string returned by the "ver" CLI command.
	// If empty, defaults to "meshcore-go".
	Version string

	// Location (decimal degrees). Nil means not set.
	Lat *float64
	Lon *float64

	// OwnerInfo is a free-form owner/contact string exposed via the "owner.info"
	// CLI key. Stored for the app to consume; not applied by the library.
	OwnerInfo string

	// Radio settings (opaque strings for software nodes without hardware).
	RadioFreq  string // frequency in MHz (e.g., "915.0")
	RadioBW    string // bandwidth in kHz (e.g., "250.0")
	RadioSF    string // spreading factor (e.g., "12")
	RadioCR    string // coding rate (e.g., "8")
	RadioModel string // radio identifier (e.g., "MQTT")

	// AppData is a pointer to the AdvertAppData used by the advert builder.
	// CLI set commands for name/lat/lon update this directly so subsequent
	// advertisements reflect the changes. May be nil.
	AppData *codec.AdvertAppData

	// OnSettingChanged is called after a CLI set command successfully updates
	// an in-memory value. The room server application uses this to persist
	// the change to the database. May be nil.
	OnSettingChanged func(key, value string)

	// OnRegionsChanged persists the region map (Router.RegionMap) when the
	// "region save" CLI command runs, receiving the map's MarshalBinary output.
	// If nil, "region save" reports that persistence is unsupported. Region
	// management commands are only available when a RegionMap is set on the
	// Router. May be nil.
	OnRegionsChanged func(data []byte) error

	// BootloaderVersion is returned by "get bootloader.ver". On Go nodes
	// (not running on NRF52 hardware), this is typically "ERROR: unsupported".
	BootloaderVersion string

	// OnReboot, if set, is invoked by the "reboot" CLI command. The library never
	// restarts the process itself; the app decides what to do. Without it,
	// "reboot" reports that it is unsupported.
	OnReboot func()

	// OnSetClock, if set, is invoked by the "time <epoch>" CLI command with the
	// requested epoch seconds. A transport-attached server usually has a better
	// (host) clock than a remote client, so accepting a client's time is opt-in.
	// Without it, "time" reports unsupported. "clock"/"clock sync" only report.
	OnSetClock func(epoch uint32) error

	// CLIHandler is an optional callback for custom CLI commands.
	// Called when no built-in command matches. Return "" for no reply,
	// or "Unknown command" to indicate unrecognized input.
	CLIHandler func(cmd string) string

	// Logger for server events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// Server is a MeshCore room server that manages clients, stores posts,
// and synchronizes messages to connected clients.
type Server struct {
	cfg    ServerConfig
	log    *slog.Logger
	mu     sync.Mutex
	cancel context.CancelFunc
	cli    *cli.Dispatcher

	// sender is the event-based response sender. When set, the event-based
	// handler methods (HandleLogin, HandleTextMessage, etc.) use this for
	// sending responses. When nil, only the legacy HandlePacket path works.
	sender NodeSender

	// Sync loop state
	nextClientIdx int
}

// SetSender sets the NodeSender used by event-based handler methods
// (HandleLogin, HandleTextMessage, HandleRequest) and the sync loop.
// This is typically called by the RoomNode during construction.
func (s *Server) SetSender(sender NodeSender) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sender = sender
}

// SetOnSettingChanged sets the callback invoked when a CLI set command
// changes a setting. This is typically called after construction to wire
// in persistence and re-advertisement logic that depends on other components.
func (s *Server) SetOnSettingChanged(fn func(key, value string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.OnSettingChanged = fn
}

// NewServer creates a room server with the given configuration.
func NewServer(cfg ServerConfig) *Server {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		cfg: cfg,
		log: logger.WithGroup("room"),
	}
	s.cli = s.buildCLI()
	return s
}

// Start begins the server's background loops (post sync). Blocks until
// the context is cancelled. Typically called in a goroutine:
//
//	go server.Start(ctx)
func (s *Server) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()

	s.runSyncLoop(ctx)
}

// Stop cancels the server's context.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
}
