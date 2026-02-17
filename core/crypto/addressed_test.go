package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptAddressed(t *testing.T) {
	kpSender, _ := GenerateKeyPair()
	kpRecipient, _ := GenerateKeyPair()

	plaintext := []byte("Hello, peer-to-peer!")

	// Sender encrypts to recipient
	encrypted, err := EncryptAddressed(plaintext, kpSender.PrivateKey, kpRecipient.PublicKey)
	if err != nil {
		t.Fatalf("EncryptAddressed() error = %v", err)
	}

	// Recipient decrypts from sender
	decrypted, err := DecryptAddressed(encrypted, kpRecipient.PrivateKey, kpSender.PublicKey)
	if err != nil {
		t.Fatalf("DecryptAddressed() error = %v", err)
	}

	// Decrypted may have trailing zero padding, so check prefix
	if !bytes.HasPrefix(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want prefix %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptAddressedWithSecret(t *testing.T) {
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()

	// Pre-compute shared secret
	secret, err := ComputeSharedSecret(kpA.PrivateKey, kpB.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret() error = %v", err)
	}

	plaintext := []byte("Using pre-computed secret")

	encrypted, err := EncryptAddressedWithSecret(plaintext, secret)
	if err != nil {
		t.Fatalf("EncryptAddressedWithSecret() error = %v", err)
	}

	decrypted, err := DecryptAddressedWithSecret(encrypted, secret)
	if err != nil {
		t.Fatalf("DecryptAddressedWithSecret() error = %v", err)
	}

	if !bytes.HasPrefix(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want prefix %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptAddressedCrossCompatible(t *testing.T) {
	// Verify that EncryptAddressed and EncryptAddressedWithSecret produce
	// data that is interchangeable with DecryptAddressed/DecryptAddressedWithSecret
	kpA, _ := GenerateKeyPair()
	kpB, _ := GenerateKeyPair()

	secret, _ := ComputeSharedSecret(kpA.PrivateKey, kpB.PublicKey)
	plaintext := []byte("Cross-compatible test")

	// Encrypt with full key derivation
	encrypted, err := EncryptAddressed(plaintext, kpA.PrivateKey, kpB.PublicKey)
	if err != nil {
		t.Fatalf("EncryptAddressed() error = %v", err)
	}

	// Decrypt with pre-computed secret
	decrypted, err := DecryptAddressedWithSecret(encrypted, secret)
	if err != nil {
		t.Fatalf("DecryptAddressedWithSecret() error = %v", err)
	}

	if !bytes.HasPrefix(decrypted, plaintext) {
		t.Errorf("cross-compatible decrypt failed: got %q, want prefix %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptAddressedWrongKey(t *testing.T) {
	kpSender, _ := GenerateKeyPair()
	kpRecipient, _ := GenerateKeyPair()
	kpWrong, _ := GenerateKeyPair()

	plaintext := []byte("Secret message")

	encrypted, err := EncryptAddressed(plaintext, kpSender.PrivateKey, kpRecipient.PublicKey)
	if err != nil {
		t.Fatalf("EncryptAddressed() error = %v", err)
	}

	// Try to decrypt with wrong key
	_, err = DecryptAddressed(encrypted, kpWrong.PrivateKey, kpSender.PublicKey)
	if err != ErrMACMismatch {
		t.Errorf("DecryptAddressed() with wrong key: error = %v, want %v", err, ErrMACMismatch)
	}
}

func TestEncryptDecryptAnonymous(t *testing.T) {
	kpRecipient, _ := GenerateKeyPair()

	plaintext := []byte("Anonymous request data")

	// Encrypt anonymously
	ephPubKey, encrypted, err := EncryptAnonymous(plaintext, kpRecipient.PublicKey)
	if err != nil {
		t.Fatalf("EncryptAnonymous() error = %v", err)
	}

	// Recipient decrypts using the ephemeral public key
	decrypted, err := DecryptAnonymous(encrypted, kpRecipient.PrivateKey, ephPubKey[:])
	if err != nil {
		t.Fatalf("DecryptAnonymous() error = %v", err)
	}

	if !bytes.HasPrefix(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want prefix %q", decrypted, plaintext)
	}
}

func TestEncryptAnonymousUniqueKeys(t *testing.T) {
	kpRecipient, _ := GenerateKeyPair()
	plaintext := []byte("test")

	// Two anonymous encryptions should use different ephemeral keys
	eph1, _, err := EncryptAnonymous(plaintext, kpRecipient.PublicKey)
	if err != nil {
		t.Fatalf("first EncryptAnonymous() error = %v", err)
	}

	eph2, _, err := EncryptAnonymous(plaintext, kpRecipient.PublicKey)
	if err != nil {
		t.Fatalf("second EncryptAnonymous() error = %v", err)
	}

	if eph1 == eph2 {
		t.Error("ephemeral keys should differ between calls")
	}
}

func TestDecryptAnonymousWrongKey(t *testing.T) {
	kpRecipient, _ := GenerateKeyPair()
	kpWrong, _ := GenerateKeyPair()

	plaintext := []byte("test")
	ephPubKey, encrypted, _ := EncryptAnonymous(plaintext, kpRecipient.PublicKey)

	// Wrong recipient
	_, err := DecryptAnonymous(encrypted, kpWrong.PrivateKey, ephPubKey[:])
	if err != ErrMACMismatch {
		t.Errorf("DecryptAnonymous() with wrong key: error = %v, want %v", err, ErrMACMismatch)
	}
}
