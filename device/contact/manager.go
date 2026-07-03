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

	// DefaultMaxAnonContacts is the default size of the transient/anonymous
	// contact pool, held in addition to MaxContacts (firmware MAX_ANON_CONTACTS).
	DefaultMaxAnonContacts = 8

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

// Compile-time assertion that ContactManager implements ContactStore.
var _ ContactStore = (*ContactManager)(nil)

// ManagerConfig configures a ContactManager.
type ManagerConfig struct {
	// MaxContacts is the maximum number of regular contacts to store.
	// Default: 32 (DefaultMaxContacts).
	MaxContacts int

	// MaxAnonContacts is the size of the transient/anonymous contact pool,
	// held in addition to MaxContacts. Transient (ADV_TYPE_NONE) contacts evict
	// only each other, never a regular contact. Default: 8.
	MaxAnonContacts int

	// OverwriteWhenFull enables overwriting the oldest non-favorite contact
	// when the list is full. When false, AddContact returns ErrContactsFull.
	OverwriteWhenFull bool

	// Logger for contact management events. Falls back to slog.Default() if nil.
	Logger *slog.Logger

	// Persistence, if set, makes the manager durable: it is seeded from
	// Persistence.Load at construction, and add/update/remove mutations are
	// mirrored to Persistence.Save/Delete. Nil keeps the manager in-memory only.
	Persistence ContactPersistence
}

// ContactManager is a thread-safe store for known mesh peers.
// It provides add, remove, and search operations with firmware-compatible
// eviction semantics.
//
// This is a standalone data structure with no dependency on the router.
type ContactManager struct {
	cfg         ManagerConfig
	log         *slog.Logger
	mu          sync.RWMutex
	contacts    []*ContactInfo
	localKey    ed25519.PrivateKey
	persistence ContactPersistence

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
	if cfg.MaxAnonContacts <= 0 {
		cfg.MaxAnonContacts = DefaultMaxAnonContacts
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	m := &ContactManager{
		cfg:      cfg,
		log:      logger.WithGroup("contacts"),
		contacts: make([]*ContactInfo, 0, cfg.MaxContacts+cfg.MaxAnonContacts),
		localKey: localPrivKey,
	}

	// Seed from the persistence backend, if any. AddContact runs here with
	// m.persistence still nil (no callbacks are registered yet either), so the
	// loaded contacts are not re-persisted. Wire the backend afterward.
	if cfg.Persistence != nil {
		loaded, err := cfg.Persistence.Load()
		if err != nil {
			m.log.Warn("failed to load persisted contacts", "error", err)
		} else {
			for _, c := range loaded {
				if _, err := m.AddContact(c); err != nil {
					break // store full
				}
			}
		}
		m.persistence = cfg.Persistence
	}

	return m
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

	stored := m.allocateSlot(c.IsTransient())
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
	m.persist(stored)

	return stored, nil
}

// UpdateContact updates mutable fields of an existing contact identified by c.ID.
// Returns ErrContactNotFound if the contact does not exist.
// This does not allocate or evict — it only updates an existing entry.
func (m *ContactManager) UpdateContact(c *ContactInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, existing := range m.contacts {
		if existing.ID == c.ID {
			existing.Name = c.Name
			existing.Type = c.Type
			existing.Flags = c.Flags
			existing.OutPathLen = c.OutPathLen
			if len(c.OutPath) > 0 {
				existing.OutPath = make([]byte, len(c.OutPath))
				copy(existing.OutPath, c.OutPath)
			} else {
				existing.OutPath = nil
			}
			existing.LastAdvertTimestamp = c.LastAdvertTimestamp
			existing.LastMod = c.LastMod
			existing.GPSLat = c.GPSLat
			existing.GPSLon = c.GPSLon
			existing.SyncSince = c.SyncSince

			if m.onContactAdded != nil {
				m.onContactAdded(existing, false)
			}
			m.persist(existing)
			return nil
		}
	}
	return ErrContactNotFound
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
			if m.persistence != nil {
				if err := m.persistence.Delete(id); err != nil {
					m.log.Debug("failed to persist contact removal", "error", err)
				}
			}
			return nil
		}
	}
	return ErrContactNotFound
}

// persist mirrors a contact to the persistence backend, if configured. Called
// with m.mu held, so the backend must not block.
func (m *ContactManager) persist(c *ContactInfo) {
	if m.persistence == nil {
		return
	}
	if err := m.persistence.Save(c); err != nil {
		m.log.Debug("failed to persist contact", "error", err)
	}
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
//
// Transient (ADV_TYPE_NONE) and regular contacts share the same backing array
// (capacity MaxContacts+MaxAnonContacts) but evict from separate pools: a
// transientOnly add recycles the oldest transient contact, while a regular add
// evicts the oldest non-favorite, non-transient contact (only when
// OverwriteWhenFull is enabled). Returns nil if no slot is available.
//
// Must be called with m.mu held for writing.
func (m *ContactManager) allocateSlot(transientOnly bool) *ContactInfo {
	// Case 1: space available. Matches firmware, where num_contacts is gated by
	// MAX_CONTACTS; the +MaxAnonContacts only sizes the backing array headroom.
	if len(m.contacts) < m.cfg.MaxContacts {
		c := &ContactInfo{}
		m.contacts = append(m.contacts, c)
		return c
	}

	// Case 2: evict. Transient adds always recycle within the anon pool;
	// regular adds only overwrite when OverwriteWhenFull is enabled.
	if !transientOnly && !m.cfg.OverwriteWhenFull {
		return nil
	}

	oldestIdx := -1
	var oldestMod uint32 = 0xFFFFFFFF

	for i, c := range m.contacts {
		if transientOnly {
			if !c.IsTransient() {
				continue
			}
		} else if c.IsFavorite() || c.IsTransient() {
			continue
		}
		if c.LastMod < oldestMod {
			oldestMod = c.LastMod
			oldestIdx = i
		}
	}

	if oldestIdx < 0 {
		// No evictable contact in the target pool.
		return nil
	}

	if m.onContactOverwrite != nil {
		m.onContactOverwrite(m.contacts[oldestIdx].ID)
	}

	// Reset the slot
	m.contacts[oldestIdx] = &ContactInfo{}
	return m.contacts[oldestIdx]
}
