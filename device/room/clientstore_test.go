package room

import (
	"sync"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
)

func makeClientID(b byte) core.MeshCoreID {
	var id core.MeshCoreID
	id[0] = b
	return id
}

func makeClient(id core.MeshCoreID, name string, perms uint8, lastActivity uint32) *ClientInfo {
	return &ClientInfo{
		ID:           id,
		Name:         name,
		Permissions:  perms,
		OutPathLen:   -1,
		LastActivity: lastActivity,
	}
}

func TestClientInfo_Role(t *testing.T) {
	c := &ClientInfo{Permissions: codec.PermACLReadWrite}
	if c.Role() != codec.PermACLReadWrite {
		t.Errorf("Role() = %d, want %d", c.Role(), codec.PermACLReadWrite)
	}

	c.Permissions = codec.PermACLAdmin | 0xF0 // extra bits should be masked
	if c.Role() != codec.PermACLAdmin {
		t.Errorf("Role() = %d, want %d", c.Role(), codec.PermACLAdmin)
	}
}

func TestClientInfo_IsAdmin(t *testing.T) {
	tests := []struct {
		perms uint8
		want  bool
	}{
		{codec.PermACLGuest, false},
		{codec.PermACLReadOnly, false},
		{codec.PermACLReadWrite, false},
		{codec.PermACLAdmin, true},
	}
	for _, tt := range tests {
		c := &ClientInfo{Permissions: tt.perms}
		if got := c.IsAdmin(); got != tt.want {
			t.Errorf("perms=%d: IsAdmin() = %v, want %v", tt.perms, got, tt.want)
		}
	}
}

func TestClientInfo_IsGuest(t *testing.T) {
	c := &ClientInfo{Permissions: codec.PermACLGuest}
	if !c.IsGuest() {
		t.Error("codec.PermACLGuest should be guest")
	}
	c.Permissions = codec.PermACLReadOnly
	if c.IsGuest() {
		t.Error("codec.PermACLReadOnly should not be guest")
	}
}

func TestClientInfo_CanWrite(t *testing.T) {
	tests := []struct {
		perms uint8
		want  bool
	}{
		{codec.PermACLGuest, false},
		{codec.PermACLReadOnly, false},
		{codec.PermACLReadWrite, true},
		{codec.PermACLAdmin, true},
	}
	for _, tt := range tests {
		c := &ClientInfo{Permissions: tt.perms}
		if got := c.CanWrite(); got != tt.want {
			t.Errorf("perms=%d: CanWrite() = %v, want %v", tt.perms, got, tt.want)
		}
	}
}

func TestClientInfo_CanRead(t *testing.T) {
	tests := []struct {
		perms uint8
		want  bool
	}{
		{codec.PermACLGuest, false},
		{codec.PermACLReadOnly, true},
		{codec.PermACLReadWrite, true},
		{codec.PermACLAdmin, true},
	}
	for _, tt := range tests {
		c := &ClientInfo{Permissions: tt.perms}
		if got := c.CanRead(); got != tt.want {
			t.Errorf("perms=%d: CanRead() = %v, want %v", tt.perms, got, tt.want)
		}
	}
}

func TestMemoryClientStore_AddClient(t *testing.T) {
	s := NewMemoryClientStore(10)
	id := makeClientID(0x01)
	c := makeClient(id, "Alice", codec.PermACLReadWrite, 100)

	stored, err := s.AddClient(c)
	if err != nil {
		t.Fatalf("AddClient failed: %v", err)
	}
	if stored.Name != "Alice" {
		t.Errorf("Name = %q, want %q", stored.Name, "Alice")
	}
	if s.Count() != 1 {
		t.Errorf("Count() = %d, want 1", s.Count())
	}
}

func TestMemoryClientStore_AddClient_UpdateExisting(t *testing.T) {
	s := NewMemoryClientStore(10)
	id := makeClientID(0x01)

	s.AddClient(makeClient(id, "Alice", codec.PermACLReadOnly, 100))

	// Add same ID with updated fields
	updated := makeClient(id, "Alice Updated", codec.PermACLReadWrite, 200)
	stored, err := s.AddClient(updated)
	if err != nil {
		t.Fatalf("AddClient update failed: %v", err)
	}
	if stored.Name != "Alice Updated" {
		t.Errorf("Name = %q, want %q", stored.Name, "Alice Updated")
	}
	if stored.Permissions != codec.PermACLReadWrite {
		t.Errorf("Permissions = %d, want %d", stored.Permissions, codec.PermACLReadWrite)
	}
	if s.Count() != 1 {
		t.Errorf("Count() = %d, want 1 (update, not add)", s.Count())
	}
}

func TestMemoryClientStore_AddClient_Full(t *testing.T) {
	s := NewMemoryClientStore(2)

	s.AddClient(makeClient(makeClientID(0x01), "A", codec.PermACLAdmin, 100))
	s.AddClient(makeClient(makeClientID(0x02), "B", codec.PermACLAdmin, 200))

	// All admins — should fail
	_, err := s.AddClient(makeClient(makeClientID(0x03), "C", codec.PermACLReadWrite, 300))
	if err != ErrClientsFull {
		t.Errorf("expected ErrClientsFull, got %v", err)
	}
}

func TestMemoryClientStore_AddClient_EvictsOldest(t *testing.T) {
	s := NewMemoryClientStore(2)

	id1 := makeClientID(0x01)
	id2 := makeClientID(0x02)
	id3 := makeClientID(0x03)

	s.AddClient(makeClient(id1, "Old", codec.PermACLReadWrite, 100)) // oldest non-admin
	s.AddClient(makeClient(id2, "New", codec.PermACLReadWrite, 200))

	stored, err := s.AddClient(makeClient(id3, "Newest", codec.PermACLReadWrite, 300))
	if err != nil {
		t.Fatalf("AddClient with eviction failed: %v", err)
	}
	if stored.Name != "Newest" {
		t.Errorf("Name = %q, want %q", stored.Name, "Newest")
	}

	// id1 should be evicted
	if s.GetClient(id1) != nil {
		t.Error("oldest non-admin should be evicted")
	}
	if s.GetClient(id2) == nil {
		t.Error("id2 should still exist")
	}
	if s.Count() != 2 {
		t.Errorf("Count() = %d, want 2", s.Count())
	}
}

func TestMemoryClientStore_AddClient_NeverEvictAdmin(t *testing.T) {
	s := NewMemoryClientStore(2)

	id1 := makeClientID(0x01)
	id2 := makeClientID(0x02)
	id3 := makeClientID(0x03)

	s.AddClient(makeClient(id1, "Admin", codec.PermACLAdmin, 100)) // oldest but admin
	s.AddClient(makeClient(id2, "User", codec.PermACLReadWrite, 200))

	stored, err := s.AddClient(makeClient(id3, "New", codec.PermACLReadWrite, 300))
	if err != nil {
		t.Fatalf("AddClient failed: %v", err)
	}
	if stored.Name != "New" {
		t.Errorf("Name = %q, want %q", stored.Name, "New")
	}

	// Admin should be preserved, id2 (non-admin, oldest non-admin) should be evicted
	if s.GetClient(id1) == nil {
		t.Error("admin should NOT be evicted")
	}
	if s.GetClient(id2) != nil {
		t.Error("oldest non-admin (id2) should be evicted")
	}
}

func TestMemoryClientStore_RemoveClient(t *testing.T) {
	s := NewMemoryClientStore(10)
	id := makeClientID(0x01)

	s.AddClient(makeClient(id, "Alice", codec.PermACLReadWrite, 100))

	if err := s.RemoveClient(id); err != nil {
		t.Fatalf("RemoveClient failed: %v", err)
	}
	if s.Count() != 0 {
		t.Errorf("Count() = %d, want 0", s.Count())
	}
	if s.GetClient(id) != nil {
		t.Error("removed client should not be found")
	}
}

func TestMemoryClientStore_RemoveClient_NotFound(t *testing.T) {
	s := NewMemoryClientStore(10)

	err := s.RemoveClient(makeClientID(0xFF))
	if err != ErrClientNotFound {
		t.Errorf("expected ErrClientNotFound, got %v", err)
	}
}

func TestMemoryClientStore_GetClient(t *testing.T) {
	s := NewMemoryClientStore(10)
	id := makeClientID(0x01)

	s.AddClient(makeClient(id, "Alice", codec.PermACLReadWrite, 100))

	found := s.GetClient(id)
	if found == nil {
		t.Fatal("GetClient returned nil")
	}
	if found.Name != "Alice" {
		t.Errorf("Name = %q, want %q", found.Name, "Alice")
	}
}

func TestMemoryClientStore_GetClient_NotFound(t *testing.T) {
	s := NewMemoryClientStore(10)

	found := s.GetClient(makeClientID(0xFF))
	if found != nil {
		t.Error("expected nil for unknown client")
	}
}

func TestMemoryClientStore_UpdateClient(t *testing.T) {
	s := NewMemoryClientStore(10)
	id := makeClientID(0x01)

	s.AddClient(makeClient(id, "Alice", codec.PermACLReadOnly, 100))

	updated := &ClientInfo{
		ID:           id,
		Name:         "Alice Updated",
		Permissions:  codec.PermACLReadWrite,
		LastActivity: 200,
		SyncSince:    500,
	}

	if err := s.UpdateClient(updated); err != nil {
		t.Fatalf("UpdateClient failed: %v", err)
	}

	found := s.GetClient(id)
	if found.Name != "Alice Updated" {
		t.Errorf("Name = %q, want %q", found.Name, "Alice Updated")
	}
	if found.Permissions != codec.PermACLReadWrite {
		t.Errorf("Permissions = %d, want %d", found.Permissions, codec.PermACLReadWrite)
	}
	if found.SyncSince != 500 {
		t.Errorf("SyncSince = %d, want 500", found.SyncSince)
	}
}

func TestMemoryClientStore_UpdateClient_NotFound(t *testing.T) {
	s := NewMemoryClientStore(10)

	err := s.UpdateClient(&ClientInfo{ID: makeClientID(0xFF)})
	if err != ErrClientNotFound {
		t.Errorf("expected ErrClientNotFound, got %v", err)
	}
}

func TestMemoryClientStore_Count(t *testing.T) {
	s := NewMemoryClientStore(10)

	if s.Count() != 0 {
		t.Errorf("empty Count() = %d, want 0", s.Count())
	}

	s.AddClient(makeClient(makeClientID(0x01), "A", codec.PermACLReadWrite, 1))
	s.AddClient(makeClient(makeClientID(0x02), "B", codec.PermACLReadWrite, 2))

	if s.Count() != 2 {
		t.Errorf("Count() = %d, want 2", s.Count())
	}
}

func TestMemoryClientStore_ForEach(t *testing.T) {
	s := NewMemoryClientStore(10)

	s.AddClient(makeClient(makeClientID(0x01), "A", codec.PermACLReadWrite, 1))
	s.AddClient(makeClient(makeClientID(0x02), "B", codec.PermACLReadWrite, 2))
	s.AddClient(makeClient(makeClientID(0x03), "C", codec.PermACLReadWrite, 3))

	var names []string
	s.ForEach(func(c *ClientInfo) bool {
		names = append(names, c.Name)
		return true
	})
	if len(names) != 3 {
		t.Errorf("ForEach visited %d clients, want 3", len(names))
	}

	// Early termination
	count := 0
	s.ForEach(func(c *ClientInfo) bool {
		count++
		return count < 2
	})
	if count != 2 {
		t.Errorf("ForEach early stop: visited %d, want 2", count)
	}
}

func TestMemoryClientStore_DefaultCapacity(t *testing.T) {
	s := NewMemoryClientStore(0)
	if s.maxClients != DefaultMaxClients {
		t.Errorf("maxClients = %d, want %d", s.maxClients, DefaultMaxClients)
	}
}

func TestMemoryClientStore_Concurrent(t *testing.T) {
	s := NewMemoryClientStore(50)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := core.MeshCoreID{byte(n), byte(n + 1)}
			s.AddClient(makeClient(id, "Node", codec.PermACLReadWrite, uint32(n)))
		}(i)
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.Count()
			id := core.MeshCoreID{byte(n), byte(n + 1)}
			s.GetClient(id)
		}(i)
	}
	wg.Wait()

	if s.Count() != 20 {
		t.Errorf("Count() = %d, want 20", s.Count())
	}
}
