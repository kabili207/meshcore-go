package room

import (
	"path/filepath"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/acl"
)

// TestClientStore_PersistenceRoundTrip verifies that an admin survives a restart
// (persisted + seeded), while non-admins and transient sync state do not.
func TestClientStore_PersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")

	var admin, member core.MeshCoreID
	admin[0] = 0x01
	member[0] = 0x02

	fs := acl.NewFileStore(path)
	s := NewMemoryClientStore(20, WithPersistence(fs))
	if _, err := s.AddClient(&ClientInfo{
		Client:    acl.Client{ID: admin, Name: "Boss", Permissions: codec.PermACLAdmin},
		SyncSince: 999, // transient: must not survive
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddClient(&ClientInfo{
		Client: acl.Client{ID: member, Permissions: codec.PermACLReadWrite},
	}); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	// Restart: a fresh store seeded from the same file.
	s2 := NewMemoryClientStore(20, WithPersistence(acl.NewFileStore(path)))

	restored := s2.GetClient(admin)
	if restored == nil {
		t.Fatal("admin not restored after restart")
	}
	if !restored.IsAdmin() || restored.Name != "Boss" {
		t.Errorf("restored admin = %+v, want admin named Boss", restored)
	}
	if restored.SyncSince != 0 {
		t.Errorf("SyncSince = %d, want 0 (transient state must not persist)", restored.SyncSince)
	}
	if s2.GetClient(member) != nil {
		t.Error("non-admin client should not be persisted")
	}
}

// TestClientStore_DemoteRemovesFromPersistence verifies that demoting an admin
// drops it from the persisted set.
func TestClientStore_DemoteRemovesFromPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	var id core.MeshCoreID
	id[0] = 0x07

	fs := acl.NewFileStore(path)
	s := NewMemoryClientStore(20, WithPersistence(fs))
	s.AddClient(&ClientInfo{Client: acl.Client{ID: id, Permissions: codec.PermACLAdmin}})
	if err := s.UpdateClient(&ClientInfo{Client: acl.Client{ID: id, Permissions: codec.PermACLReadWrite}}); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := NewMemoryClientStore(20, WithPersistence(acl.NewFileStore(path)))
	if s2.GetClient(id) != nil {
		t.Error("demoted (non-admin) client should not persist")
	}
}

// TestClientStore_RemoveDeletesFromPersistence verifies RemoveClient clears the
// persisted entry.
func TestClientStore_RemoveDeletesFromPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	var id core.MeshCoreID
	id[0] = 0x09

	fs := acl.NewFileStore(path)
	s := NewMemoryClientStore(20, WithPersistence(fs))
	s.AddClient(&ClientInfo{Client: acl.Client{ID: id, Permissions: codec.PermACLAdmin}})
	if err := s.RemoveClient(id); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := NewMemoryClientStore(20, WithPersistence(acl.NewFileStore(path)))
	if s2.GetClient(id) != nil {
		t.Error("removed admin should not persist")
	}
}
