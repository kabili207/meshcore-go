package contact

import "github.com/kabili207/meshcore-go/core"

// ContactStore is the interface for contact storage backends.
// The default in-memory implementation is ContactManager.
// Custom implementations can provide database-backed or other persistent storage.
//
// Implementations must return pointers to internally-held ContactInfo structs
// from GetByPubKey and SearchByHash (not copies), so that callers can read
// fields directly. Mutations should go through UpdateContact.
type ContactStore interface {
	// AddContact adds a new contact. Returns a pointer to the stored contact.
	// If the store is full and overwrite is enabled, the oldest non-favorite
	// contact is evicted. Returns ErrContactsFull if no slot is available.
	AddContact(c *ContactInfo) (*ContactInfo, error)

	// UpdateContact updates mutable fields of an existing contact identified
	// by c.ID. Returns ErrContactNotFound if the contact does not exist.
	// Does not allocate or evict — only updates an existing entry.
	UpdateContact(c *ContactInfo) error

	// RemoveContact removes the contact with the given public key.
	// Returns ErrContactNotFound if no matching contact exists.
	RemoveContact(id core.MeshCoreID) error

	// GetByPubKey returns the contact with the exact public key, or nil if
	// not found. The returned pointer references internal storage.
	GetByPubKey(id core.MeshCoreID) *ContactInfo

	// SearchByHash returns contacts whose public key hash (first byte) matches
	// the given hash. Up to MaxSearchResults may be returned due to collisions.
	SearchByHash(hash uint8) []*ContactInfo

	// GetSharedSecret finds the contact and returns the cached ECDH shared
	// secret, computing it lazily if needed.
	GetSharedSecret(id core.MeshCoreID) ([]byte, error)

	// Count returns the number of stored contacts.
	Count() int

	// ForEach calls fn for each contact. Return false from fn to stop iteration.
	ForEach(fn func(c *ContactInfo) bool)
}

// ContactPersistence is an optional durable backend for a ContactManager. When
// configured (ManagerConfig.Persistence), the manager seeds itself from Load at
// construction and mirrors add/update/remove mutations to Save/Delete, keeping
// the in-memory store as the fast read path.
//
// Save and Delete are called while the manager holds its lock, so implementations
// must return quickly (queue/debounce actual I/O rather than blocking). See
// FileContactStore for a JSON-file implementation.
type ContactPersistence interface {
	// Load returns all persisted contacts, used to seed the manager on startup.
	Load() ([]*ContactInfo, error)

	// Save persists a contact (insert or update).
	Save(c *ContactInfo) error

	// Delete removes a persisted contact by public key.
	Delete(id core.MeshCoreID) error
}
