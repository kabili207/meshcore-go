package contact

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/crypto"
)

func generateTestKeyPair(t *testing.T) *crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return kp
}

func makeTestContact(pubKey ed25519.PublicKey) *ContactInfo {
	var id core.MeshCoreID
	copy(id[:], pubKey)
	return &ContactInfo{
		ID:         id,
		Name:       "TestNode",
		Type:       0x01, // NodeTypeChat
		OutPathLen: PathUnknown,
	}
}

func TestContactInfo_IsFavorite(t *testing.T) {
	c := &ContactInfo{}
	if c.IsFavorite() {
		t.Error("new contact should not be favorite")
	}

	c.Flags = FlagFavorite
	if !c.IsFavorite() {
		t.Error("contact with FlagFavorite should be favorite")
	}

	// Other flags should not affect favorite status
	c.Flags = 0xFE // all bits except bit 0
	if c.IsFavorite() {
		t.Error("contact without bit 0 set should not be favorite")
	}
}

func TestContactInfo_SetFavorite(t *testing.T) {
	c := &ContactInfo{Flags: 0x04} // some other flag set

	c.SetFavorite(true)
	if !c.IsFavorite() {
		t.Error("SetFavorite(true) should set favorite")
	}
	if c.Flags&0x04 == 0 {
		t.Error("SetFavorite should preserve other flags")
	}

	c.SetFavorite(false)
	if c.IsFavorite() {
		t.Error("SetFavorite(false) should clear favorite")
	}
	if c.Flags&0x04 == 0 {
		t.Error("SetFavorite(false) should preserve other flags")
	}
}

func TestContactInfo_HasDirectPath(t *testing.T) {
	c := &ContactInfo{OutPathLen: PathUnknown}
	if c.HasDirectPath() {
		t.Error("PathUnknown should not have direct path")
	}

	c.OutPathLen = 0
	if !c.HasDirectPath() {
		t.Error("OutPathLen 0 (zero-hop) should have direct path")
	}

	c.OutPathLen = 3
	if !c.HasDirectPath() {
		t.Error("OutPathLen 3 should have direct path")
	}
}

func TestContactInfo_GetSharedSecret(t *testing.T) {
	localKP := generateTestKeyPair(t)
	remoteKP := generateTestKeyPair(t)
	c := makeTestContact(remoteKP.PublicKey)

	// First call: computes the secret
	secret1, err := c.GetSharedSecret(localKP.PrivateKey)
	if err != nil {
		t.Fatalf("GetSharedSecret failed: %v", err)
	}
	if len(secret1) != 32 {
		t.Fatalf("expected 32-byte secret, got %d", len(secret1))
	}

	// Second call: should return the cached value
	secret2, err := c.GetSharedSecret(localKP.PrivateKey)
	if err != nil {
		t.Fatalf("GetSharedSecret cached call failed: %v", err)
	}
	if string(secret1) != string(secret2) {
		t.Error("cached secret should match first computation")
	}

	// Verify it matches a direct computation
	directSecret, err := crypto.ComputeSharedSecret(localKP.PrivateKey, remoteKP.PublicKey)
	if err != nil {
		t.Fatalf("direct ComputeSharedSecret failed: %v", err)
	}
	if string(secret1) != string(directSecret) {
		t.Error("cached secret should match direct computation")
	}
}

func TestContactInfo_GetSharedSecret_Symmetric(t *testing.T) {
	localKP := generateTestKeyPair(t)
	remoteKP := generateTestKeyPair(t)

	// Local computing secret with remote's pubkey
	localContact := makeTestContact(remoteKP.PublicKey)
	secretA, err := localContact.GetSharedSecret(localKP.PrivateKey)
	if err != nil {
		t.Fatalf("GetSharedSecret A failed: %v", err)
	}

	// Remote computing secret with local's pubkey
	remoteContact := makeTestContact(localKP.PublicKey)
	secretB, err := remoteContact.GetSharedSecret(remoteKP.PrivateKey)
	if err != nil {
		t.Fatalf("GetSharedSecret B failed: %v", err)
	}

	if string(secretA) != string(secretB) {
		t.Error("ECDH shared secrets should be symmetric")
	}
}

func TestContactInfo_InvalidateSharedSecret(t *testing.T) {
	localKP := generateTestKeyPair(t)
	remoteKP := generateTestKeyPair(t)
	c := makeTestContact(remoteKP.PublicKey)

	// Compute and cache
	_, err := c.GetSharedSecret(localKP.PrivateKey)
	if err != nil {
		t.Fatalf("initial GetSharedSecret failed: %v", err)
	}

	// Invalidate
	c.InvalidateSharedSecret()

	// Should recompute (verify no error)
	secret, err := c.GetSharedSecret(localKP.PrivateKey)
	if err != nil {
		t.Fatalf("GetSharedSecret after invalidation failed: %v", err)
	}
	if len(secret) != 32 {
		t.Error("recomputed secret should be 32 bytes")
	}
}

func TestContactInfo_GetSharedSecret_InvalidKey(t *testing.T) {
	localKP := generateTestKeyPair(t)

	// Contact with a zeroed public key
	c := &ContactInfo{}
	_, err := c.GetSharedSecret(localKP.PrivateKey)
	// The result depends on the curve25519 implementation. With all-zeros,
	// the conversion from Ed25519 to X25519 may fail or produce a low-order point.
	// We just verify it doesn't panic.
	_ = err
}

func TestContactInfo_GetSharedSecret_Concurrent(t *testing.T) {
	localKP := generateTestKeyPair(t)
	remoteKP := generateTestKeyPair(t)
	c := makeTestContact(remoteKP.PublicKey)

	// Run concurrent GetSharedSecret calls — race detector should catch issues
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			secret, err := c.GetSharedSecret(localKP.PrivateKey)
			if err != nil {
				t.Errorf("concurrent GetSharedSecret failed: %v", err)
			}
			if len(secret) != 32 {
				t.Errorf("expected 32-byte secret, got %d", len(secret))
			}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestContactInfo_Defaults(t *testing.T) {
	c := &ContactInfo{}

	if c.IsFavorite() {
		t.Error("zero-value contact should not be favorite")
	}
	// Zero-value OutPathLen is 0 (zero-hop direct), which is HasDirectPath() == true.
	// Code that creates contacts with unknown paths must explicitly set PathUnknown.
	if !c.HasDirectPath() {
		t.Error("zero-value OutPathLen (0) should report HasDirectPath == true")
	}

	c.OutPathLen = PathUnknown
	if c.HasDirectPath() {
		t.Error("PathUnknown should report HasDirectPath == false")
	}
}

func init() {
	// Ensure crypto/rand is seeded (Go handles this automatically, but
	// this prevents any issues with test key generation).
	buf := make([]byte, 1)
	_, _ = rand.Read(buf)
}
