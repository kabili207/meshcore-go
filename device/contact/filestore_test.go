package contact

import (
	"path/filepath"
	"testing"

	"github.com/kabili207/meshcore-go/core"
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
