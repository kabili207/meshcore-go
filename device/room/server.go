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

	// Sync loop state
	nextClientIdx int
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
	return &Server{
		cfg: cfg,
		log: logger.WithGroup("room"),
	}
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
