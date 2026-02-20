package room

import (
	"errors"

	"github.com/kabili207/meshcore-go/core"
)

var (
	// ErrClientNotFound is returned when a client lookup fails.
	ErrClientNotFound = errors.New("client not found")

	// ErrClientsFull is returned when the client list is full and no slot
	// could be allocated.
	ErrClientsFull = errors.New("client list full")
)

// ClientStore is the interface for client storage backends.
// The default in-memory implementation is MemoryClientStore.
//
// Implementations must return pointers to internally-held ClientInfo structs
// from GetClient (not copies), so callers can read fields directly.
type ClientStore interface {
	// AddClient adds a new client or updates an existing one (matched by ID).
	// Returns the stored client. Returns ErrClientsFull if no slot is available.
	AddClient(c *ClientInfo) (*ClientInfo, error)

	// RemoveClient removes the client with the given public key.
	// Returns ErrClientNotFound if not found.
	RemoveClient(id core.MeshCoreID) error

	// GetClient returns the client with the given public key, or nil if not found.
	GetClient(id core.MeshCoreID) *ClientInfo

	// UpdateClient updates mutable fields of an existing client identified by c.ID.
	// Returns ErrClientNotFound if the client does not exist.
	UpdateClient(c *ClientInfo) error

	// Count returns the number of stored clients.
	Count() int

	// ForEach calls fn for each client. Return false from fn to stop iteration.
	ForEach(fn func(c *ClientInfo) bool)
}
