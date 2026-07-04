package node

import (
	"crypto/ed25519"
	"testing"

	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/room"
)

// newTestRoom builds a minimal RoomNode through NewRoom, the same path
// production callers use. It deliberately leaves Room.Router unset so the router
// must be threaded in by NewRoom itself (roomCfg.Router = base.Router).
func newTestRoom(t *testing.T) *RoomNode {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	priv := ed25519.PrivateKey(kp.PrivateKey)
	n, err := NewRoom(RoomConfig{
		PrivateKey: priv,
		Contacts:   contact.NewManager(priv, contact.ManagerConfig{}),
		Room: room.ServerConfig{
			AdminPassword: "adminpw",
			Clients:       room.NewMemoryClientStore(20),
			Posts:         room.NewMemoryPostStore(100),
		},
	})
	if err != nil {
		t.Fatalf("new room: %v", err)
	}
	return n
}

// TestNewRoom_RouterCLIKeys is a regression test for a nil-pointer panic where
// NewRoom failed to thread the base node's router into the room server's
// ServerConfig. The router-backed CLI keys (path.hash.mode, loop.detect,
// flood.max) dereference ServerConfig.Router, so a server built via NewRoom
// panicked on set/load for those keys. The existing room package tests build
// room.Server directly and set Router themselves, so they never covered this.
func TestNewRoom_RouterCLIKeys(t *testing.T) {
	srv := newTestRoom(t).Server()

	// LoadConfig routes through the same ConfigKey.Set a CLI "set" uses. Before
	// the fix this panicked with a nil Router receiver.
	if err := srv.LoadConfig("path.hash.mode", "2"); err != nil {
		t.Fatalf("LoadConfig(path.hash.mode): %v", err)
	}
	if got, ok := srv.GetConfig("path.hash.mode"); !ok || got != "2" {
		t.Errorf("path.hash.mode = %q (ok=%v), want \"2\"", got, ok)
	}

	// The other router-backed keys must not panic either.
	for _, kv := range []struct{ key, val string }{
		{"loop.detect", "strict"},
		{"flood.max", "48"},
	} {
		if err := srv.LoadConfig(kv.key, kv.val); err != nil {
			t.Errorf("LoadConfig(%s=%s): %v", kv.key, kv.val, err)
		}
	}
}
