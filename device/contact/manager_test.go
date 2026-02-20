package contact

import (
	"sync"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/crypto"
)

func makeIDWithHash(hash byte) core.MeshCoreID {
	var id core.MeshCoreID
	id[0] = hash
	// Set remaining bytes to something unique based on hash to avoid collisions
	id[1] = hash + 1
	id[2] = hash + 2
	return id
}

func makeContactWithID(id core.MeshCoreID, name string, lastMod uint32) *ContactInfo {
	return &ContactInfo{
		ID:         id,
		Name:       name,
		Type:       0x01,
		OutPathLen: PathUnknown,
		LastMod:    lastMod,
	}
}

func newTestManager(t *testing.T, maxContacts int, overwrite bool) *ContactManager {
	t.Helper()
	kp := generateTestKeyPair(t)
	return NewManager(kp.PrivateKey, ManagerConfig{
		MaxContacts:       maxContacts,
		OverwriteWhenFull: overwrite,
	})
}

func TestManager_NewManager_Defaults(t *testing.T) {
	kp := generateTestKeyPair(t)
	m := NewManager(kp.PrivateKey, ManagerConfig{})

	if m.cfg.MaxContacts != DefaultMaxContacts {
		t.Errorf("default MaxContacts = %d, want %d", m.cfg.MaxContacts, DefaultMaxContacts)
	}
	if m.Count() != 0 {
		t.Errorf("new manager should have 0 contacts, got %d", m.Count())
	}
}

func TestManager_AddContact(t *testing.T) {
	m := newTestManager(t, 10, false)
	id := makeIDWithHash(0xAA)
	c := makeContactWithID(id, "Alice", 100)

	stored, err := m.AddContact(c)
	if err != nil {
		t.Fatalf("AddContact failed: %v", err)
	}
	if stored.Name != "Alice" {
		t.Errorf("stored name = %q, want %q", stored.Name, "Alice")
	}
	if m.Count() != 1 {
		t.Errorf("Count() = %d, want 1", m.Count())
	}

	// Retrieve by pubkey
	found := m.GetByPubKey(id)
	if found == nil {
		t.Fatal("GetByPubKey returned nil")
	}
	if found.Name != "Alice" {
		t.Errorf("found name = %q, want %q", found.Name, "Alice")
	}
}

func TestManager_AddContact_Full(t *testing.T) {
	m := newTestManager(t, 2, false)

	id1 := makeIDWithHash(0x01)
	id2 := makeIDWithHash(0x02)
	id3 := makeIDWithHash(0x03)

	if _, err := m.AddContact(makeContactWithID(id1, "A", 1)); err != nil {
		t.Fatalf("AddContact 1 failed: %v", err)
	}
	if _, err := m.AddContact(makeContactWithID(id2, "B", 2)); err != nil {
		t.Fatalf("AddContact 2 failed: %v", err)
	}

	_, err := m.AddContact(makeContactWithID(id3, "C", 3))
	if err != ErrContactsFull {
		t.Errorf("expected ErrContactsFull, got %v", err)
	}
	if m.Count() != 2 {
		t.Errorf("Count() = %d, want 2", m.Count())
	}
}

func TestManager_AddContact_OverwriteOldest(t *testing.T) {
	m := newTestManager(t, 2, true)

	id1 := makeIDWithHash(0x01)
	id2 := makeIDWithHash(0x02)
	id3 := makeIDWithHash(0x03)

	m.AddContact(makeContactWithID(id1, "OldNode", 100)) // oldest by LastMod
	m.AddContact(makeContactWithID(id2, "NewNode", 200))

	var overwrittenID core.MeshCoreID
	m.SetOnContactOverwrite(func(id core.MeshCoreID) {
		overwrittenID = id
	})

	stored, err := m.AddContact(makeContactWithID(id3, "Newest", 300))
	if err != nil {
		t.Fatalf("AddContact with overwrite failed: %v", err)
	}
	if stored.Name != "Newest" {
		t.Errorf("stored name = %q, want %q", stored.Name, "Newest")
	}

	// The oldest (id1, LastMod=100) should have been evicted
	if overwrittenID != id1 {
		t.Error("expected oldest contact to be evicted")
	}
	if m.GetByPubKey(id1) != nil {
		t.Error("evicted contact should not be found")
	}
	if m.Count() != 2 {
		t.Errorf("Count() = %d, want 2", m.Count())
	}
}

func TestManager_AddContact_NeverEvictFavorite(t *testing.T) {
	m := newTestManager(t, 2, true)

	id1 := makeIDWithHash(0x01)
	id2 := makeIDWithHash(0x02)
	id3 := makeIDWithHash(0x03)

	c1 := makeContactWithID(id1, "Fav1", 100)
	c1.Flags = FlagFavorite
	c2 := makeContactWithID(id2, "Fav2", 200)
	c2.Flags = FlagFavorite

	m.AddContact(c1)
	m.AddContact(c2)

	// Both are favorites — should fail even with overwrite enabled
	_, err := m.AddContact(makeContactWithID(id3, "New", 300))
	if err != ErrContactsFull {
		t.Errorf("expected ErrContactsFull when all are favorites, got %v", err)
	}
}

func TestManager_AddContact_InvalidatesSecret(t *testing.T) {
	localKP := generateTestKeyPair(t)
	remoteKP := generateTestKeyPair(t)
	m := NewManager(localKP.PrivateKey, ManagerConfig{MaxContacts: 10})

	var remoteID core.MeshCoreID
	copy(remoteID[:], remoteKP.PublicKey)

	c := makeContactWithID(remoteID, "Peer", 100)
	stored, err := m.AddContact(c)
	if err != nil {
		t.Fatalf("AddContact failed: %v", err)
	}

	// The shared secret should not be valid after add
	stored.mu.Lock()
	valid := stored.sharedSecretValid
	stored.mu.Unlock()
	if valid {
		t.Error("shared secret should be invalidated after AddContact")
	}

	// But GetSharedSecret should work (computes lazily)
	secret, err := m.GetSharedSecret(remoteID)
	if err != nil {
		t.Fatalf("GetSharedSecret failed: %v", err)
	}
	if len(secret) != 32 {
		t.Errorf("expected 32-byte secret, got %d", len(secret))
	}
}

func TestManager_UpdateContact(t *testing.T) {
	m := newTestManager(t, 10, false)
	id := makeIDWithHash(0xAA)

	m.AddContact(makeContactWithID(id, "Alice", 100))

	updated := &ContactInfo{
		ID:                 id,
		Name:               "Alice Updated",
		Type:               0x02,
		Flags:              FlagFavorite,
		OutPathLen:         3,
		OutPath:            []byte{0x01, 0x02, 0x03},
		LastAdvertTimestamp: 2000,
		LastMod:            200,
		GPSLat:             37774900,
		GPSLon:             -122419400,
		SyncSince:          500,
	}

	if err := m.UpdateContact(updated); err != nil {
		t.Fatalf("UpdateContact failed: %v", err)
	}

	found := m.GetByPubKey(id)
	if found == nil {
		t.Fatal("contact not found after update")
	}
	if found.Name != "Alice Updated" {
		t.Errorf("Name = %q, want %q", found.Name, "Alice Updated")
	}
	if found.Type != 0x02 {
		t.Errorf("Type = %d, want 2", found.Type)
	}
	if !found.IsFavorite() {
		t.Error("expected favorite flag set")
	}
	if found.OutPathLen != 3 {
		t.Errorf("OutPathLen = %d, want 3", found.OutPathLen)
	}
	if len(found.OutPath) != 3 || found.OutPath[0] != 0x01 {
		t.Error("OutPath not updated correctly")
	}
	if found.LastAdvertTimestamp != 2000 {
		t.Errorf("LastAdvertTimestamp = %d, want 2000", found.LastAdvertTimestamp)
	}
	if found.LastMod != 200 {
		t.Errorf("LastMod = %d, want 200", found.LastMod)
	}
	if found.GPSLat != 37774900 {
		t.Errorf("GPSLat = %d, want 37774900", found.GPSLat)
	}
	if found.SyncSince != 500 {
		t.Errorf("SyncSince = %d, want 500", found.SyncSince)
	}

	// Count should not change
	if m.Count() != 1 {
		t.Errorf("Count() = %d, want 1", m.Count())
	}
}

func TestManager_UpdateContact_NotFound(t *testing.T) {
	m := newTestManager(t, 10, false)
	id := makeIDWithHash(0xCC)

	err := m.UpdateContact(&ContactInfo{ID: id, Name: "Ghost"})
	if err != ErrContactNotFound {
		t.Errorf("expected ErrContactNotFound, got %v", err)
	}
}

func TestManager_UpdateContact_ClearsPath(t *testing.T) {
	m := newTestManager(t, 10, false)
	id := makeIDWithHash(0xAA)

	c := makeContactWithID(id, "Alice", 100)
	c.OutPathLen = 2
	c.OutPath = []byte{0x01, 0x02}
	m.AddContact(c)

	// Update with no path
	updated := &ContactInfo{
		ID:         id,
		Name:       "Alice",
		OutPathLen: PathUnknown,
	}
	if err := m.UpdateContact(updated); err != nil {
		t.Fatalf("UpdateContact failed: %v", err)
	}

	found := m.GetByPubKey(id)
	if found.OutPath != nil {
		t.Error("expected OutPath to be nil after clearing")
	}
	if found.OutPathLen != PathUnknown {
		t.Errorf("OutPathLen = %d, want %d", found.OutPathLen, PathUnknown)
	}
}

func TestManager_RemoveContact(t *testing.T) {
	m := newTestManager(t, 10, false)
	id := makeIDWithHash(0xBB)
	m.AddContact(makeContactWithID(id, "Bob", 100))

	var removedID core.MeshCoreID
	m.SetOnContactRemoved(func(id core.MeshCoreID) {
		removedID = id
	})

	if err := m.RemoveContact(id); err != nil {
		t.Fatalf("RemoveContact failed: %v", err)
	}
	if m.Count() != 0 {
		t.Errorf("Count() = %d, want 0", m.Count())
	}
	if m.GetByPubKey(id) != nil {
		t.Error("removed contact should not be found")
	}
	if removedID != id {
		t.Error("OnContactRemoved callback should have fired with correct ID")
	}
}

func TestManager_RemoveContact_NotFound(t *testing.T) {
	m := newTestManager(t, 10, false)
	id := makeIDWithHash(0xCC)

	err := m.RemoveContact(id)
	if err != ErrContactNotFound {
		t.Errorf("expected ErrContactNotFound, got %v", err)
	}
}

func TestManager_RemoveContact_Compact(t *testing.T) {
	m := newTestManager(t, 10, false)

	id1 := makeIDWithHash(0x01)
	id2 := makeIDWithHash(0x02)
	id3 := makeIDWithHash(0x03)

	m.AddContact(makeContactWithID(id1, "A", 1))
	m.AddContact(makeContactWithID(id2, "B", 2))
	m.AddContact(makeContactWithID(id3, "C", 3))

	// Remove middle element
	if err := m.RemoveContact(id2); err != nil {
		t.Fatalf("RemoveContact failed: %v", err)
	}

	if m.Count() != 2 {
		t.Errorf("Count() = %d, want 2", m.Count())
	}

	// Remaining should still be findable
	if m.GetByPubKey(id1) == nil {
		t.Error("id1 should still be present")
	}
	if m.GetByPubKey(id3) == nil {
		t.Error("id3 should still be present")
	}
}

func TestManager_GetByPubKey_NotFound(t *testing.T) {
	m := newTestManager(t, 10, false)
	id := makeIDWithHash(0xDD)

	if found := m.GetByPubKey(id); found != nil {
		t.Error("expected nil for non-existent contact")
	}
}

func TestManager_SearchByHash(t *testing.T) {
	m := newTestManager(t, 10, false)

	// Create contacts with the same hash (first byte) but different keys
	id1 := makeIDWithHash(0xAA)
	id2 := core.MeshCoreID{0xAA, 0x10, 0x20} // same hash, different key
	id3 := makeIDWithHash(0xBB)               // different hash

	m.AddContact(makeContactWithID(id1, "A", 1))
	m.AddContact(makeContactWithID(id2, "B", 2))
	m.AddContact(makeContactWithID(id3, "C", 3))

	results := m.SearchByHash(0xAA)
	if len(results) != 2 {
		t.Fatalf("SearchByHash(0xAA) returned %d results, want 2", len(results))
	}

	results = m.SearchByHash(0xBB)
	if len(results) != 1 {
		t.Fatalf("SearchByHash(0xBB) returned %d results, want 1", len(results))
	}

	results = m.SearchByHash(0xCC)
	if len(results) != 0 {
		t.Fatalf("SearchByHash(0xCC) returned %d results, want 0", len(results))
	}
}

func TestManager_SearchByHash_MaxResults(t *testing.T) {
	m := newTestManager(t, 20, false)

	// Add more contacts with the same hash than MaxSearchResults
	for i := 0; i < MaxSearchResults+5; i++ {
		id := core.MeshCoreID{0xAA, byte(i), byte(i + 10)}
		m.AddContact(makeContactWithID(id, "Node", uint32(i)))
	}

	results := m.SearchByHash(0xAA)
	if len(results) != MaxSearchResults {
		t.Errorf("SearchByHash returned %d results, want max %d", len(results), MaxSearchResults)
	}
}

func TestManager_GetSharedSecret(t *testing.T) {
	localKP := generateTestKeyPair(t)
	remoteKP := generateTestKeyPair(t)
	m := NewManager(localKP.PrivateKey, ManagerConfig{MaxContacts: 10})

	var remoteID core.MeshCoreID
	copy(remoteID[:], remoteKP.PublicKey)

	m.AddContact(makeContactWithID(remoteID, "Peer", 100))

	secret, err := m.GetSharedSecret(remoteID)
	if err != nil {
		t.Fatalf("GetSharedSecret failed: %v", err)
	}

	// Verify it's symmetric with the remote's perspective
	directSecret, err := crypto.ComputeSharedSecret(remoteKP.PrivateKey, localKP.PublicKey)
	if err != nil {
		t.Fatalf("direct ComputeSharedSecret failed: %v", err)
	}
	if string(secret) != string(directSecret) {
		t.Error("manager's shared secret should match direct computation")
	}
}

func TestManager_GetSharedSecret_NotFound(t *testing.T) {
	m := newTestManager(t, 10, false)
	id := makeIDWithHash(0xEE)

	_, err := m.GetSharedSecret(id)
	if err != ErrContactNotFound {
		t.Errorf("expected ErrContactNotFound, got %v", err)
	}
}

func TestManager_Count(t *testing.T) {
	m := newTestManager(t, 10, false)

	if m.Count() != 0 {
		t.Errorf("empty Count() = %d, want 0", m.Count())
	}

	id1 := makeIDWithHash(0x01)
	id2 := makeIDWithHash(0x02)

	m.AddContact(makeContactWithID(id1, "A", 1))
	if m.Count() != 1 {
		t.Errorf("Count() after 1 add = %d, want 1", m.Count())
	}

	m.AddContact(makeContactWithID(id2, "B", 2))
	if m.Count() != 2 {
		t.Errorf("Count() after 2 adds = %d, want 2", m.Count())
	}

	m.RemoveContact(id1)
	if m.Count() != 1 {
		t.Errorf("Count() after remove = %d, want 1", m.Count())
	}
}

func TestManager_ForEach(t *testing.T) {
	m := newTestManager(t, 10, false)

	id1 := makeIDWithHash(0x01)
	id2 := makeIDWithHash(0x02)
	id3 := makeIDWithHash(0x03)

	m.AddContact(makeContactWithID(id1, "A", 1))
	m.AddContact(makeContactWithID(id2, "B", 2))
	m.AddContact(makeContactWithID(id3, "C", 3))

	// Collect all names
	var names []string
	m.ForEach(func(c *ContactInfo) bool {
		names = append(names, c.Name)
		return true
	})
	if len(names) != 3 {
		t.Errorf("ForEach visited %d contacts, want 3", len(names))
	}

	// Early termination
	count := 0
	m.ForEach(func(c *ContactInfo) bool {
		count++
		return count < 2 // stop after 2
	})
	if count != 2 {
		t.Errorf("ForEach with early stop visited %d contacts, want 2", count)
	}
}

func TestManager_AddContactCallback(t *testing.T) {
	m := newTestManager(t, 10, false)

	var callbackContact *ContactInfo
	var callbackIsNew bool
	m.SetOnContactAdded(func(contact *ContactInfo, isNew bool) {
		callbackContact = contact
		callbackIsNew = isNew
	})

	id := makeIDWithHash(0x01)
	m.AddContact(makeContactWithID(id, "A", 1))

	if callbackContact == nil {
		t.Fatal("OnContactAdded callback was not called")
	}
	if callbackContact.Name != "A" {
		t.Errorf("callback contact name = %q, want %q", callbackContact.Name, "A")
	}
	if !callbackIsNew {
		t.Error("expected isNew = true for new contact")
	}
}

func TestManager_Concurrent(t *testing.T) {
	m := newTestManager(t, 100, false)

	var wg sync.WaitGroup

	// Concurrent adds
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := core.MeshCoreID{byte(n), byte(n + 1), byte(n + 2)}
			m.AddContact(makeContactWithID(id, "Node", uint32(n)))
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			m.Count()
			m.SearchByHash(byte(n))
			id := core.MeshCoreID{byte(n), byte(n + 1), byte(n + 2)}
			m.GetByPubKey(id)
		}(i)
	}

	wg.Wait()

	if m.Count() != 20 {
		t.Errorf("Count() = %d after concurrent adds, want 20", m.Count())
	}
}

func TestManager_OverwriteEvictsCorrectContact(t *testing.T) {
	m := newTestManager(t, 3, true)

	id1 := makeIDWithHash(0x01)
	id2 := makeIDWithHash(0x02)
	id3 := makeIDWithHash(0x03)
	id4 := makeIDWithHash(0x04)

	m.AddContact(makeContactWithID(id1, "Middle", 200))
	m.AddContact(makeContactWithID(id2, "Oldest", 100)) // lowest LastMod
	m.AddContact(makeContactWithID(id3, "Newest", 300))

	// Mark id2 as favorite — it's the oldest but should not be evicted
	found := m.GetByPubKey(id2)
	found.SetFavorite(true)

	// Now id1 (LastMod=200) is the oldest non-favorite
	stored, err := m.AddContact(makeContactWithID(id4, "New", 400))
	if err != nil {
		t.Fatalf("AddContact failed: %v", err)
	}
	if stored.Name != "New" {
		t.Errorf("stored name = %q, want %q", stored.Name, "New")
	}

	// id1 should have been evicted (oldest non-favorite)
	if m.GetByPubKey(id1) != nil {
		t.Error("id1 (oldest non-favorite) should have been evicted")
	}
	// id2 (favorite) should still be present
	if m.GetByPubKey(id2) == nil {
		t.Error("id2 (favorite) should NOT have been evicted")
	}
}
