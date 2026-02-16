package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestEd25519PubKeyToX25519(t *testing.T) {
	// Generate a real Ed25519 key pair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	result, err := Ed25519PubKeyToX25519([]byte(pub))
	if err != nil {
		t.Fatalf("Ed25519PubKeyToX25519() error = %v", err)
	}

	if len(result) != 32 {
		t.Errorf("result length = %d, want 32", len(result))
	}

	// Converting the same key twice should produce the same result
	result2, err := Ed25519PubKeyToX25519([]byte(pub))
	if err != nil {
		t.Fatalf("Ed25519PubKeyToX25519() second call error = %v", err)
	}

	for i := range result {
		if result[i] != result2[i] {
			t.Errorf("result not deterministic at byte %d: %02x != %02x", i, result[i], result2[i])
		}
	}
}

func TestEd25519PubKeyToX25519WrongLength(t *testing.T) {
	shortKey := make([]byte, 16)

	_, err := Ed25519PubKeyToX25519(shortKey)
	if err == nil {
		t.Error("Ed25519PubKeyToX25519() should error on wrong length key")
	}
}
