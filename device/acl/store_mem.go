package acl

import (
	"sync"

	"github.com/kabili207/meshcore-go/core"
)

// DefaultMaxClients is the default client-store capacity (firmware MAX_CLIENTS = 20).
const DefaultMaxClients = 20

var _ Store = (*MemoryStore)(nil)

// MemoryStore is an in-memory Store. When full, it evicts the least-recently
// active non-admin client, matching the firmware's ClientACL behavior.
type MemoryStore struct {
	mu         sync.RWMutex
	clients    []*Client
	maxClients int
}

// NewMemoryStore creates an in-memory store with the given capacity.
// If maxClients is 0, DefaultMaxClients is used.
func NewMemoryStore(maxClients int) *MemoryStore {
	if maxClients <= 0 {
		maxClients = DefaultMaxClients
	}
	return &MemoryStore{
		clients:    make([]*Client, 0, maxClients),
		maxClients: maxClients,
	}
}

// AddClient adds a client or updates an existing one. If the store is full, the
// least-recently-active non-admin client is evicted. Returns ErrClientsFull if
// all clients are admins and no slot is available.
func (s *MemoryStore) AddClient(c *Client) (*Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.clients {
		if existing.ID == c.ID {
			copyClientFields(existing, c)
			return existing, nil
		}
	}

	slot := s.allocateSlot()
	if slot == nil {
		return nil, ErrClientsFull
	}
	copyClientFields(slot, c)
	slot.ID = c.ID
	return slot, nil
}

// RemoveClient removes the client with the given public key.
func (s *MemoryStore) RemoveClient(id core.MeshCoreID) error {
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
func (s *MemoryStore) GetClient(id core.MeshCoreID) *Client {
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
func (s *MemoryStore) UpdateClient(c *Client) error {
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
func (s *MemoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

// ForEach calls fn for each client. Return false to stop.
func (s *MemoryStore) ForEach(fn func(c *Client) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, c := range s.clients {
		if !fn(c) {
			return
		}
	}
}

// allocateSlot returns a pointer to a new or evicted client slot, or nil if the
// store is full of admins. Must be called with s.mu held for writing.
func (s *MemoryStore) allocateSlot() *Client {
	if len(s.clients) < s.maxClients {
		c := &Client{}
		s.clients = append(s.clients, c)
		return c
	}

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

	s.clients[oldestIdx] = &Client{}
	return s.clients[oldestIdx]
}

// copyClientFields copies mutable fields from src to dst (not the slot pointer).
func copyClientFields(dst, src *Client) {
	dst.ID = src.ID
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
}
