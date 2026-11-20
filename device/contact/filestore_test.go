package contact

import (
	"bytes"
	"path/filepath"
	"sync"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
)

func TestFileContactStore_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "contacts.json")

	fs := NewFileContactStore(path)
	var id core.MeshCoreID
	id[0] = 0xAB
	if err := fs.Save(&ContactInfo{
		ID:         id,
		Name:       "Alice",
		Type:       2,
		OutPathLen: 1,
		OutPath:    []byte{0x05, 0x06},
	}); err != nil {
		t.Fatal(err)
	}
	if err := fs.Flush(); err != nil {
		t.Fatal(err)
	}

	// A fresh store reading the same file sees the contact.
	loaded, err := NewFileContactStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 contact, got %d", len(loaded))
	}
	c := loaded[0]
	if c.ID != id || c.Name != "Alice" || c.Type != 2 || c.OutPathLen != 1 {
		t.Errorf("round-trip mismatch: %+v", c)
	}
	if len(c.OutPath) != 2 || c.OutPath[0] != 0x05 {
		t.Errorf("out path mismatch: %x", c.OutPath)
	}
}

func TestFileContactStore_LoadMissingFile(t *testing.T) {
	loaded, err := NewFileContactStore(filepath.Join(t.TempDir(), "nope.json")).Load()
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(loaded) != 0 {
		t.Errorf("expected no contacts, got %d", len(loaded))
	}
}

func TestContactManager_PersistenceSeedsOnRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "contacts.json")
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Use a real remote key so the seeded contact can derive a shared secret.
	remote, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var id core.MeshCoreID
	copy(id[:], remote.PublicKey)

	// First run: add a contact, then flush to disk.
	fs := NewFileContactStore(path)
	m := NewManager(kp.PrivateKey, ManagerConfig{Persistence: fs})
	if _, err := m.AddContact(&ContactInfo{ID: id, Name: "Bob", OutPathLen: PathUnknown}); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	// Second run: a new manager backed by the same file is seeded.
	m2 := NewManager(kp.PrivateKey, ManagerConfig{Persistence: NewFileContactStore(path)})
	got := m2.GetByPubKey(id)
	if got == nil {
		t.Fatal("contact was not seeded from persistence after restart")
	}
	if got.Name != "Bob" {
		t.Errorf("name = %q, want Bob", got.Name)
	}
	// A seeded pubkey still derives a shared secret.
	if _, err := m2.GetSharedSecret(id); err != nil {
		t.Errorf("shared secret from seeded contact: %v", err)
	}
}

func TestContactManager_PersistenceDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "contacts.json")
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var id core.MeshCoreID
	id[0] = 0xEF

	fs := NewFileContactStore(path)
	m := NewManager(kp.PrivateKey, ManagerConfig{Persistence: fs})
	m.AddContact(&ContactInfo{ID: id, Name: "Carol", OutPathLen: PathUnknown})
	if err := m.RemoveContact(id); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	m2 := NewManager(kp.PrivateKey, ManagerConfig{Persistence: NewFileContactStore(path)})
	if m2.GetByPubKey(id) != nil {
		t.Error("removed contact should not be seeded after restart")
	}
}

func TestContactManager_PersistenceEviction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "contacts.json")
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var oldID, newID core.MeshCoreID
	oldID[0] = 0x01
	newID[0] = 0x02

	fs := NewFileContactStore(path)
	m := NewManager(kp.PrivateKey, ManagerConfig{MaxContacts: 1, OverwriteWhenFull: true, Persistence: fs})
	m.AddContact(&ContactInfo{ID: oldID, Name: "Old", Type: 1, OutPathLen: PathUnknown, LastMod: 1})
	m.AddContact(&ContactInfo{ID: newID, Name: "New", Type: 1, OutPathLen: PathUnknown, LastMod: 2})
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	m2 := NewManager(kp.PrivateKey, ManagerConfig{MaxContacts: 8, Persistence: NewFileContactStore(path)})
	if m2.GetByPubKey(oldID) != nil {
		t.Error("evicted contact should not be seeded after restart")
	}
	if m2.GetByPubKey(newID) == nil {
		t.Error("surviving contact was not seeded after restart")
	}
}

func TestContactManager_UpdateWithStoredPointerKeepsPath(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var id core.MeshCoreID
	id[0] = 0x03

	m := NewManager(kp.PrivateKey, ManagerConfig{})
	stored, err := m.AddContact(&ContactInfo{ID: id, OutPathLen: 2, OutPath: []byte{0x0A, 0x0B}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateContact(stored); err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x0A, 0x0B}; !bytes.Equal(stored.OutPath, want) {
		t.Errorf("OutPath = %x, want %x", stored.OutPath, want)
	}
}

func TestProcessPath_Persists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "contacts.json")
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var id core.MeshCoreID
	id[0] = 0x04

	fs := NewFileContactStore(path)
	m := NewManager(kp.PrivateKey, ManagerConfig{Persistence: fs})
	m.AddContact(&ContactInfo{ID: id, OutPathLen: PathUnknown})
	content := &codec.PathContent{PathLen: 2, Path: []byte{0x0A, 0x0B}}
	if _, _, _, err := ProcessPath(m, id, content, 100); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	got := NewManager(kp.PrivateKey, ManagerConfig{Persistence: NewFileContactStore(path)}).GetByPubKey(id)
	if got == nil {
		t.Fatal("contact was not seeded after restart")
	}
	if got.OutPathLen != 2 || !bytes.Equal(got.OutPath, content.Path) {
		t.Errorf("path = %d/%x, want 2/%x", got.OutPathLen, got.OutPath, content.Path)
	}
}

func TestFileContactStore_ConcurrentFlush(t *testing.T) {
	fs := NewFileContactStore(filepath.Join(t.TempDir(), "contacts.json"))

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fs.Flush(); err != nil {
				t.Errorf("Flush: %v", err)
			}
		}()
	}
	wg.Wait()
}
