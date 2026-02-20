// Package connection provides keep-alive and timeout tracking for connected
// mesh peers.
//
// The Manager tracks when each peer was last seen and fires a disconnect
// callback when a peer's inactivity exceeds the configured timeout. The
// timeout is calculated as KeepAliveInterval × TimeoutMultiplier (firmware
// uses 2.5×).
//
// This corresponds to the firmware's keep_alive_millis, last_activity, and
// checkConnections() logic in BaseChatMesh.
package connection

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/kabili207/meshcore-go/core"
)

const (
	// DefaultKeepAliveInterval is the default interval between keep-alive
	// messages. Peers that haven't been heard from within
	// KeepAliveInterval × TimeoutMultiplier are considered disconnected.
	DefaultKeepAliveInterval = 30 * time.Second

	// DefaultTimeoutMultiplier is the default multiplier applied to
	// KeepAliveInterval to determine the disconnect timeout.
	// Firmware uses 2.5 (5/2).
	DefaultTimeoutMultiplier = 2.5

	// checkInterval is the resolution of the manager's timeout check loop.
	checkInterval = time.Second
)

// PeerState tracks a connected peer's activity.
type PeerState struct {
	ID       core.MeshCoreID
	LastSeen time.Time
}

// ManagerConfig configures a connection Manager.
type ManagerConfig struct {
	// KeepAliveInterval is the expected interval between keep-alive messages.
	// Default: 30 seconds.
	KeepAliveInterval time.Duration

	// TimeoutMultiplier is applied to KeepAliveInterval to determine when
	// a peer is considered disconnected. Default: 2.5.
	TimeoutMultiplier float64

	// Logger for connection events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// Manager tracks connected peers and detects timeouts.
type Manager struct {
	cfg     ManagerConfig
	log     *slog.Logger
	mu      sync.Mutex
	peers   map[core.MeshCoreID]*PeerState
	onDisconnect func(id core.MeshCoreID)
	cancel  context.CancelFunc

	// nowFn allows overriding time.Now() for testing.
	nowFn func() time.Time
}

// NewManager creates a connection manager with the given configuration.
func NewManager(cfg ManagerConfig) *Manager {
	if cfg.KeepAliveInterval <= 0 {
		cfg.KeepAliveInterval = DefaultKeepAliveInterval
	}
	if cfg.TimeoutMultiplier <= 0 {
		cfg.TimeoutMultiplier = DefaultTimeoutMultiplier
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		cfg:   cfg,
		log:   logger.WithGroup("connection"),
		peers: make(map[core.MeshCoreID]*PeerState),
		nowFn: time.Now,
	}
}

// SetOnDisconnect sets the callback invoked when a peer is disconnected
// due to keep-alive timeout.
func (m *Manager) SetOnDisconnect(fn func(id core.MeshCoreID)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onDisconnect = fn
}

// Register adds a peer to the connection tracker. If the peer is already
// tracked, its LastSeen time is updated (equivalent to Touch).
func (m *Manager) Register(id core.MeshCoreID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers[id] = &PeerState{
		ID:       id,
		LastSeen: m.nowFn(),
	}
}

// Touch updates the last-seen time for a peer. Does nothing if the peer
// is not tracked.
func (m *Manager) Touch(id core.MeshCoreID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.peers[id]; ok {
		p.LastSeen = m.nowFn()
	}
}

// Remove explicitly removes a peer from the tracker. The OnDisconnect
// callback is NOT called (use this for graceful disconnects).
func (m *Manager) Remove(id core.MeshCoreID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.peers, id)
}

// IsConnected returns true if the peer is currently tracked.
func (m *Manager) IsConnected(id core.MeshCoreID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.peers[id]
	return ok
}

// ConnectedCount returns the number of tracked peers.
func (m *Manager) ConnectedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.peers)
}

// CheckTimeouts checks all tracked peers for keep-alive timeout and removes
// those that have exceeded the timeout threshold.
func (m *Manager) CheckTimeouts() {
	m.mu.Lock()
	now := m.nowFn()
	timeout := time.Duration(float64(m.cfg.KeepAliveInterval) * m.cfg.TimeoutMultiplier)

	var disconnected []core.MeshCoreID
	for id, p := range m.peers {
		if now.Sub(p.LastSeen) > timeout {
			disconnected = append(disconnected, id)
		}
	}

	for _, id := range disconnected {
		delete(m.peers, id)
	}

	onDisconnect := m.onDisconnect
	m.mu.Unlock()

	// Fire callbacks outside the lock
	if onDisconnect != nil {
		for _, id := range disconnected {
			m.log.Debug("peer timed out", "peer", id.String())
			onDisconnect(id)
		}
	}
}

// Start begins the periodic timeout check loop. Blocks until the context
// is cancelled.
func (m *Manager) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	m.mu.Lock()
	m.cancel = cancel
	m.mu.Unlock()

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.CheckTimeouts()
		}
	}
}

// Stop cancels the manager's context, stopping the timeout check loop.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
}
