package contact

import (
	"crypto/ed25519"
	"errors"
	"log/slog"
	"sync"

	"github.com/kabili207/meshcore-go/core"
)

const (
	// DefaultMaxContacts is the default maximum number of contacts.
	DefaultMaxContacts = 32

	// MaxSearchResults is the maximum number of results returned by SearchByHash.
	// Multiple contacts may share the same 1-byte hash (collision).
	MaxSearchResults = 8
)

var (
	// ErrContactsFull is returned when the contact list is full and no slot
	// could be allocated (overwrite disabled or all contacts are favorites).
	ErrContactsFull = errors.New("contact list full")

	// ErrContactNotFound is returned when a contact lookup fails.
	ErrContactNotFound = errors.New("contact not found")
)

// ManagerConfig configures a ContactManager.
type ManagerConfig struct {
	// MaxContacts is the maximum number of contacts to store.
	// Default: 32 (DefaultMaxContacts).
	MaxContacts int

	// OverwriteWhenFull enables overwriting the oldest non-favorite contact
	// when the list is full. When false, AddContact returns ErrContactsFull.
	OverwriteWhenFull bool

	// Logger for contact management events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// ContactManager is a thread-safe store for known mesh peers.
// It provides add, remove, and search operations with firmware-compatible
// eviction semantics.
//
// This is a standalone data structure with no dependency on the router.
type ContactManager struct {
	cfg      ManagerConfig
	log      *slog.Logger
	mu       sync.RWMutex
	contacts []*ContactInfo
	localKey ed25519.PrivateKey

	onContactAdded     func(contact *ContactInfo, isNew bool)
	onContactRemoved   func(id core.MeshCoreID)
	onContactOverwrite func(id core.MeshCoreID)
}

// NewManager creates a ContactManager with the given configuration.
// localPrivKey is this node's Ed25519 private key, used for ECDH shared
// secret computation via GetSharedSecret.
func NewManager(localPrivKey ed25519.PrivateKey, cfg ManagerConfig) *ContactManager {
	if cfg.MaxContacts <= 0 {
		cfg.MaxContacts = DefaultMaxContacts
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &ContactManager{
		cfg:      cfg,
		log:      logger.WithGroup("contacts"),
		contacts: make([]*ContactInfo, 0, cfg.MaxContacts),
		localKey: localPrivKey,
	}
}

// SetOnContactAdded sets the callback invoked when a contact is added or updated.
// isNew is true for newly added contacts, false for updates.
func (m *ContactManager) SetOnContactAdded(fn func(contact *ContactInfo, isNew bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onContactAdded = fn
}

// SetOnContactRemoved sets the callback invoked when a contact is removed.
func (m *ContactManager) SetOnContactRemoved(fn func(id core.MeshCoreID)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onContactRemoved = fn
}

// SetOnContactOverwrite sets the callback invoked before a contact is evicted
// to make room for a new one (when OverwriteWhenFull is true).
func (m *ContactManager) SetOnContactOverwrite(fn func(id core.MeshCoreID)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onContactOverwrite = fn
}

// AddContact adds a contact to the manager. If the list is full and
// OverwriteWhenFull is true, the oldest non-favorite contact is evicted.
//
// The contact's shared secret is always invalidated on add (forcing
// recomputation on next access), matching firmware behavior.
//
// Returns a pointer to the stored contact. The caller should not hold
// references to the input ContactInfo after calling AddContact.
func (m *ContactManager) AddContact(c *ContactInfo) (*ContactInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored := m.allocateSlot()
	if stored == nil {
		return nil, ErrContactsFull
	}

	// Copy fields into the allocated slot
	stored.ID = c.ID
	stored.Name = c.Name
	stored.Type = c.Type
	stored.Flags = c.Flags
	stored.OutPathLen = c.OutPathLen
	if len(c.OutPath) > 0 {
		stored.OutPath = make([]byte, len(c.OutPath))
		copy(stored.OutPath, c.OutPath)
	} else {
		stored.OutPath = nil
	}
	stored.LastAdvertTimestamp = c.LastAdvertTimestamp
	stored.LastMod = c.LastMod
	stored.GPSLat = c.GPSLat
	stored.GPSLon = c.GPSLon
	stored.SyncSince = c.SyncSince

	// Always invalidate shared secret on add (firmware behavior)
	stored.InvalidateSharedSecret()

	if m.onContactAdded != nil {
		m.onContactAdded(stored, true)
	}

	return stored, nil
}

// RemoveContact removes the contact matching the given public key.
// Returns ErrContactNotFound if no matching contact exists.
func (m *ContactManager) RemoveContact(id core.MeshCoreID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, c := range m.contacts {
		if c.ID == id {
			// Compact: shift remaining elements left
			copy(m.contacts[i:], m.contacts[i+1:])
			m.contacts[len(m.contacts)-1] = nil // avoid memory leak
			m.contacts = m.contacts[:len(m.contacts)-1]

			if m.onContactRemoved != nil {
				m.onContactRemoved(id)
			}
			return nil
		}
	}
	return ErrContactNotFound
}

// GetByPubKey returns the contact with the exact public key, or nil if not found.
func (m *ContactManager) GetByPubKey(id core.MeshCoreID) *ContactInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, c := range m.contacts {
		if c.ID == id {
			return c
		}
	}
	return nil
}

// SearchByHash returns contacts whose public key hash (first byte) matches
// the given hash. Due to hash collisions, up to MaxSearchResults (8) contacts
// may be returned.
func (m *ContactManager) SearchByHash(hash uint8) []*ContactInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []*ContactInfo
	for _, c := range m.contacts {
		if c.ID.Hash() == hash {
			results = append(results, c)
			if len(results) >= MaxSearchResults {
				break
			}
		}
	}
	return results
}

// GetSharedSecret finds the contact by public key and returns the cached
// ECDH shared secret, computing it lazily if needed.
func (m *ContactManager) GetSharedSecret(id core.MeshCoreID) ([]byte, error) {
	c := m.GetByPubKey(id)
	if c == nil {
		return nil, ErrContactNotFound
	}
	return c.GetSharedSecret(m.localKey)
}

// Count returns the number of stored contacts.
func (m *ContactManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.contacts)
}

// ForEach calls fn for each contact. Return false from fn to stop iteration.
// Holds a read lock for the duration of iteration.
func (m *ContactManager) ForEach(fn func(c *ContactInfo) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, c := range m.contacts {
		if !fn(c) {
			return
		}
	}
}

// allocateSlot returns a pointer to an available contact slot.
// If the list is full and OverwriteWhenFull is enabled, evicts the oldest
// non-favorite contact (by LastMod timestamp). Returns nil if no slot is available.
//
// Must be called with m.mu held for writing.
func (m *ContactManager) allocateSlot() *ContactInfo {
	// Case 1: space available
	if len(m.contacts) < m.cfg.MaxContacts {
		c := &ContactInfo{}
		m.contacts = append(m.contacts, c)
		return c
	}

	// Case 2: overwrite oldest non-favorite
	if !m.cfg.OverwriteWhenFull {
		return nil
	}

	oldestIdx := -1
	var oldestMod uint32 = 0xFFFFFFFF

	for i, c := range m.contacts {
		if c.IsFavorite() {
			continue
		}
		if c.LastMod < oldestMod {
			oldestMod = c.LastMod
			oldestIdx = i
		}
	}

	if oldestIdx < 0 {
		// All contacts are favorites
		return nil
	}

	if m.onContactOverwrite != nil {
		m.onContactOverwrite(m.contacts[oldestIdx].ID)
	}

	// Reset the slot
	m.contacts[oldestIdx] = &ContactInfo{}
	return m.contacts[oldestIdx]
}
