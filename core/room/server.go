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

	"github.com/kabili207/meshcore-go/core/ack"
	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/contact"
	"github.com/kabili207/meshcore-go/core/router"
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
