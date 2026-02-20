package room

import (
	"sync"

	"github.com/kabili207/meshcore-go/core"
)

const (
	// DefaultMaxClients is the default maximum number of clients.
	// Firmware uses MAX_CLIENTS = 20.
	DefaultMaxClients = 20
)

// Compile-time assertion that MemoryClientStore implements ClientStore.
var _ ClientStore = (*MemoryClientStore)(nil)

// MemoryClientStore is an in-memory implementation of ClientStore.
type MemoryClientStore struct {
	mu         sync.RWMutex
	clients    []*ClientInfo
	maxClients int
}

// NewMemoryClientStore creates an in-memory client store with the given capacity.
// If maxClients is 0, DefaultMaxClients is used.
func NewMemoryClientStore(maxClients int) *MemoryClientStore {
	if maxClients <= 0 {
		maxClients = DefaultMaxClients
	}
	return &MemoryClientStore{
		clients:    make([]*ClientInfo, 0, maxClients),
		maxClients: maxClients,
	}
}

// AddClient adds a client or updates an existing one. If the store is full,
// the least-recently-active non-admin client is evicted. Returns ErrClientsFull
// if all clients are admins and no slot is available.
func (s *MemoryClientStore) AddClient(c *ClientInfo) (*ClientInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for existing client
	for _, existing := range s.clients {
		if existing.ID == c.ID {
			copyClientFields(existing, c)
			return existing, nil
		}
	}

	// Allocate new slot
	slot := s.allocateSlot()
	if slot == nil {
		return nil, ErrClientsFull
	}
	copyClientFields(slot, c)
	slot.ID = c.ID
	return slot, nil
}

// RemoveClient removes the client with the given public key.
func (s *MemoryClientStore) RemoveClient(id core.MeshCoreID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, c := range s.clients {
		if c.ID == id {
			copy(s.clients[i:], s.clients[i+1:])
			s.clients[len(s.clients)-1] = nil
			s.clients = s.clients[:len(s.clients)-1]
			return nil
		}
	}
	return ErrClientNotFound
}

// GetClient returns the client with the given public key, or nil.
func (s *MemoryClientStore) GetClient(id core.MeshCoreID) *ClientInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, c := range s.clients {
		if c.ID == id {
			return c
		}
	}
	return nil
}

// UpdateClient updates mutable fields of an existing client.
func (s *MemoryClientStore) UpdateClient(c *ClientInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.clients {
		if existing.ID == c.ID {
			copyClientFields(existing, c)
			return nil
		}
	}
	return ErrClientNotFound
}

// Count returns the number of stored clients.
func (s *MemoryClientStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

// ForEach calls fn for each client. Return false to stop.
func (s *MemoryClientStore) ForEach(fn func(c *ClientInfo) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, c := range s.clients {
		if !fn(c) {
			return
		}
	}
}

// allocateSlot returns a pointer to a new or evicted client slot.
// Must be called with s.mu held for writing.
func (s *MemoryClientStore) allocateSlot() *ClientInfo {
	if len(s.clients) < s.maxClients {
		c := &ClientInfo{}
		s.clients = append(s.clients, c)
		return c
	}

	// Evict least-recently-active non-admin
	oldestIdx := -1
	var oldestActivity uint32 = 0xFFFFFFFF

	for i, c := range s.clients {
		if c.IsAdmin() {
			continue
		}
		if c.LastActivity < oldestActivity {
			oldestActivity = c.LastActivity
			oldestIdx = i
		}
	}

	if oldestIdx < 0 {
		return nil // all admins
	}

	s.clients[oldestIdx] = &ClientInfo{}
	return s.clients[oldestIdx]
}

// copyClientFields copies mutable fields from src to dst (not ID).
func copyClientFields(dst, src *ClientInfo) {
	dst.Name = src.Name
	dst.Permissions = src.Permissions
	dst.OutPathLen = src.OutPathLen
	if len(src.OutPath) > 0 {
		dst.OutPath = make([]byte, len(src.OutPath))
		copy(dst.OutPath, src.OutPath)
	} else {
		dst.OutPath = nil
	}
	dst.LastTimestamp = src.LastTimestamp
	dst.LastActivity = src.LastActivity
	dst.SyncSince = src.SyncSince
	dst.PushPostTimestamp = src.PushPostTimestamp
	dst.PushFailures = src.PushFailures
}
