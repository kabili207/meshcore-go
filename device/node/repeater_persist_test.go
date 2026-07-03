package node

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/acl"
	"github.com/kabili207/meshcore-go/transport"
)

// TestRepeaterACLPersistence verifies that an admin who logs in survives a
// repeater restart when ACLPersistence is configured.
func TestRepeaterACLPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl.json")

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	client, _ := crypto.GenerateKeyPair()

	// First run: admin logs in, then flush the ACL to disk.
	fs := acl.NewFileStore(path)
	n, err := NewRepeater(RepeaterConfig{
		PrivateKey:     ed25519.PrivateKey(kp.PrivateKey),
		AdminPassword:  "adminpw",
		ACLPersistence: fs,
	})
	if err != nil {
		t.Fatal(err)
	}
	n.base.processPacket(buildRepeaterLogin(t, n, client, 100, "adminpw"), transport.PacketSourceMQTT)
	if c := n.acl.GetClient(clientID(client)); c == nil || !c.IsAdmin() {
		t.Fatal("precondition: admin not registered on first run")
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	// Second run (same identity + file): the admin is seeded without re-login.
	n2, err := NewRepeater(RepeaterConfig{
		PrivateKey:     ed25519.PrivateKey(kp.PrivateKey),
		AdminPassword:  "adminpw",
		ACLPersistence: acl.NewFileStore(path),
	})
	if err != nil {
		t.Fatal(err)
	}
	c := n2.acl.GetClient(clientID(client))
	if c == nil {
		t.Fatal("admin not restored from persistence after restart")
	}
	if !c.IsAdmin() {
		t.Errorf("restored client perms = %d, want admin", c.Permissions)
	}
}
