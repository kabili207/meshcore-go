package acl

import (
	"path/filepath"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
)

func TestACLFileStore_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl.json")
	fs := NewFileStore(path)

	var id core.MeshCoreID
	id[0] = 0xAB
	if err := fs.Save(&Client{
		ID:          id,
		Name:        "Admin",
		Permissions: codec.PermACLAdmin,
		OutPathLen:  1,
		OutPath:     []byte{0x05},
	}); err != nil {
		t.Fatal(err)
	}
	if err := fs.Flush(); err != nil {
		t.Fatal(err)
	}

	loaded, err := NewFileStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 client, got %d", len(loaded))
	}
	if loaded[0].ID != id || loaded[0].Name != "Admin" || !loaded[0].IsAdmin() {
		t.Errorf("round-trip mismatch: %+v", loaded[0])
	}
}

func TestMemoryStore_PersistsAdminsOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl.json")

	var admin, guest core.MeshCoreID
	admin[0] = 0x01
	guest[0] = 0x02

	fs := NewFileStore(path)
	s := NewMemoryStore(20, WithPersistence(fs))
	if _, err := s.AddClient(&Client{ID: admin, Permissions: codec.PermACLAdmin}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddClient(&Client{ID: guest, Permissions: codec.PermACLGuest}); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	// A fresh store seeded from the same file has the admin, not the guest.
	s2 := NewMemoryStore(20, WithPersistence(NewFileStore(path)))
	if s2.GetClient(admin) == nil {
		t.Error("admin should persist across restart")
	}
	if s2.GetClient(guest) != nil {
		t.Error("guest should not be persisted")
	}
}

func TestMemoryStore_DemoteRemovesFromPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl.json")

	var id core.MeshCoreID
	id[0] = 0x07

	fs := NewFileStore(path)
	s := NewMemoryStore(20, WithPersistence(fs))
	s.AddClient(&Client{ID: id, Permissions: codec.PermACLAdmin})
	// Demote to guest — should be dropped from persistence.
	if err := s.UpdateClient(&Client{ID: id, Permissions: codec.PermACLGuest}); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := NewMemoryStore(20, WithPersistence(NewFileStore(path)))
	if s2.GetClient(id) != nil {
		t.Error("demoted (non-admin) client should not persist")
	}
}
