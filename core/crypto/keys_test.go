package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	if len(kp.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("PublicKey length = %d, want %d", len(kp.PublicKey), ed25519.PublicKeySize)
	}
	if len(kp.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("PrivateKey length = %d, want %d", len(kp.PrivateKey), ed25519.PrivateKeySize)
	}

	// Two generated keys should differ
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() second call error = %v", err)
	}
	if kp.PublicKey.Equal(kp2.PublicKey) {
		t.Error("two generated keys should not be equal")
	}
}

func TestKeyPairFromPrivateKey(t *testing.T) {
	// Generate a key pair, then reconstruct from the private key
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	kp, err := KeyPairFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("KeyPairFromPrivateKey() error = %v", err)
	}

	if !kp.PublicKey.Equal(pub) {
		t.Error("reconstructed public key does not match original")
	}
}

func TestKeyPairFromPrivateKeyInvalidLength(t *testing.T) {
	_, err := KeyPairFromPrivateKey(make([]byte, 32))
	if err != ErrInvalidPrivKeySize {
		t.Errorf("error = %v, want %v", err, ErrInvalidPrivKeySize)
	}
}

func TestKeyPairHash(t *testing.T) {
	kp, _ := GenerateKeyPair()
	hash := kp.Hash()
	if hash != kp.PublicKey[0] {
		t.Errorf("Hash() = %02x, want %02x", hash, kp.PublicKey[0])
	}
}

func TestEd25519PubKeyToX25519(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	result, err := Ed25519PubKeyToX25519([]byte(pub))
	if err != nil {
		t.Fatalf("Ed25519PubKeyToX25519() error = %v", err)
	}

	if len(result) != 32 {
		t.Errorf("result length = %d, want 32", len(result))
	}

	// Deterministic
	result2, _ := Ed25519PubKeyToX25519([]byte(pub))
	for i := range result {
		if result[i] != result2[i] {
			t.Fatalf("result not deterministic at byte %d", i)
		}
	}
}

func TestEd25519PubKeyToX25519WrongLength(t *testing.T) {
	_, err := Ed25519PubKeyToX25519(make([]byte, 16))
	if err == nil {
		t.Error("should error on wrong length key")
	}
}

func TestEd25519PrivKeyToX25519(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	x25519Key, err := Ed25519PrivKeyToX25519(priv)
	if err != nil {
		t.Fatalf("Ed25519PrivKeyToX25519() error = %v", err)
	}

	if len(x25519Key) != 32 {
		t.Errorf("length = %d, want 32", len(x25519Key))
	}

	// Verify clamping: lowest 3 bits of first byte should be clear
	if x25519Key[0]&0x07 != 0 {
		t.Errorf("lowest 3 bits not cleared: %02x", x25519Key[0])
	}
	// Bit 255 (highest bit of byte 31) should be clear
	if x25519Key[31]&0x80 != 0 {
		t.Errorf("bit 255 not cleared: %02x", x25519Key[31])
	}
	// Bit 254 should be set
	if x25519Key[31]&0x40 == 0 {
		t.Errorf("bit 254 not set: %02x", x25519Key[31])
	}
}

func TestEd25519PrivKeyToX25519InvalidLength(t *testing.T) {
	_, err := Ed25519PrivKeyToX25519(make([]byte, 32))
	if err != ErrInvalidPrivKeySize {
		t.Errorf("error = %v, want %v", err, ErrInvalidPrivKeySize)
	}
}

func TestComputeSharedSecret(t *testing.T) {
	// Generate two key pairs
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()

	// A derives shared secret with B's public key
	secretAB, err := ComputeSharedSecret(kpA.PrivateKey, kpB.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret(A→B) error = %v", err)
	}

	// B derives shared secret with A's public key
	secretBA, err := ComputeSharedSecret(kpB.PrivateKey, kpA.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret(B→A) error = %v", err)
	}

	// Both should be equal (ECDH symmetry)
	if len(secretAB) != 32 {
		t.Errorf("secret length = %d, want 32", len(secretAB))
	}
	for i := range secretAB {
		if secretAB[i] != secretBA[i] {
			t.Fatalf("shared secrets differ at byte %d: %02x != %02x", i, secretAB[i], secretBA[i])
		}
	}
}

func TestComputeSharedSecretInvalidPubKey(t *testing.T) {
	kp, _ := GenerateKeyPair()

	_, err := ComputeSharedSecret(kp.PrivateKey, make([]byte, 16))
	if err == nil {
		t.Error("should error on wrong length public key")
	}
}
