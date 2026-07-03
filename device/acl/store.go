package acl

import (
	"errors"

	"github.com/kabili207/meshcore-go/core"
)

var (
	// ErrClientsFull is returned when the store has no room for a new client
	// (and none can be evicted, e.g. all slots are admins).
	ErrClientsFull = errors.New("client store is full")

	// ErrClientNotFound is returned when a lookup or update targets an
	// unknown client.
	ErrClientNotFound = errors.New("client not found")
)

// Store holds authenticated clients keyed by public key. Implementations may be
// in-memory or persistent.
type Store interface {
	// AddClient adds a new client or updates an existing one (matched by ID).
	// Returns the stored client, or ErrClientsFull if no slot is available.
	AddClient(c *Client) (*Client, error)

	// RemoveClient removes the client with the given public key.
	// Returns ErrClientNotFound if not found.
	RemoveClient(id core.MeshCoreID) error

	// GetClient returns the client with the given public key, or nil.
	GetClient(id core.MeshCoreID) *Client

	// UpdateClient updates mutable fields of an existing client identified by
	// c.ID. Returns ErrClientNotFound if the client does not exist.
	UpdateClient(c *Client) error

	// Count returns the number of stored clients.
	Count() int

	// ForEach calls fn for each client. Return false from fn to stop iteration.
	ForEach(fn func(c *Client) bool)
}

// Persistence is an optional durable backend for a MemoryStore. When configured
// (WithPersistence), the store seeds itself from Load at construction and mirrors
// admin clients to Save/Delete on mutation. Following firmware, only admin
// clients are persisted; guests are transient. Save and Delete are called while
// the store holds its lock, so implementations must return quickly (queue/debounce
// I/O). See FileStore for a JSON-file implementation.
type Persistence interface {
	// Load returns the persisted (admin) clients, used to seed on startup.
	Load() ([]*Client, error)

	// Save persists a client (insert or update).
	Save(c *Client) error

	// Delete removes a persisted client by public key.
	Delete(id core.MeshCoreID) error
}
