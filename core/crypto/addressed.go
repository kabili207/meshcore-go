package crypto

import (
	"crypto/ed25519"
	"fmt"
)

// EncryptAddressed encrypts plaintext for an addressed (peer-to-peer) MeshCore message.
// Uses the same AES-128 ECB + HMAC-SHA256 cipher as group messages, but keyed with
// an ECDH shared secret derived from the sender's private key and recipient's public key.
// Returns [MAC(2) || ciphertext].
func EncryptAddressed(plaintext []byte, localPrivKey ed25519.PrivateKey, remotePubKey []byte) ([]byte, error) {
	secret, err := ComputeSharedSecret(localPrivKey, remotePubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}
	return encryptThenMAC(secret, plaintext)
}

// DecryptAddressed decrypts an addressed (peer-to-peer) MeshCore message.
// Expects data as [MAC(2) || ciphertext].
// Returns the decrypted plaintext (may have trailing zero padding).
func DecryptAddressed(data []byte, localPrivKey ed25519.PrivateKey, remotePubKey []byte) ([]byte, error) {
	secret, err := ComputeSharedSecret(localPrivKey, remotePubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}
	return macThenDecrypt(secret, data)
}

// EncryptAddressedWithSecret encrypts using a pre-computed shared secret.
// Use this when the shared secret has already been derived via ComputeSharedSecret,
// to avoid recomputing it for every message to the same peer.
func EncryptAddressedWithSecret(plaintext, sharedSecret []byte) ([]byte, error) {
	return encryptThenMAC(sharedSecret, plaintext)
}

// DecryptAddressedWithSecret decrypts using a pre-computed shared secret.
func DecryptAddressedWithSecret(data, sharedSecret []byte) ([]byte, error) {
	return macThenDecrypt(sharedSecret, data)
}

// EncryptAnonymous encrypts plaintext for an anonymous request.
// Generates an ephemeral Ed25519 key pair, derives a shared secret with the
// recipient's public key, and encrypts the plaintext.
// Returns the ephemeral public key (to include in the ANON_REQ payload) and
// the encrypted data [MAC(2) || ciphertext].
func EncryptAnonymous(plaintext []byte, recipientPubKey []byte) (ephemeralPubKey [32]byte, encrypted []byte, err error) {
	// Generate ephemeral key pair
	kp, err := GenerateKeyPair()
	if err != nil {
		return ephemeralPubKey, nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	copy(ephemeralPubKey[:], kp.PublicKey)

	secret, err := ComputeSharedSecret(kp.PrivateKey, recipientPubKey)
	if err != nil {
		return ephemeralPubKey, nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	encrypted, err = encryptThenMAC(secret, plaintext)
	if err != nil {
		return ephemeralPubKey, nil, err
	}

	return ephemeralPubKey, encrypted, nil
}

// DecryptAnonymous decrypts an anonymous request using the recipient's private key
// and the ephemeral public key included in the ANON_REQ payload.
func DecryptAnonymous(data []byte, localPrivKey ed25519.PrivateKey, ephemeralPubKey []byte) ([]byte, error) {
	secret, err := ComputeSharedSecret(localPrivKey, ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}
	return macThenDecrypt(secret, data)
}
