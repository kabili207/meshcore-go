package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

var (
	ErrInvalidPubKeySize  = errors.New("invalid public key size: expected 32 bytes")
	ErrInvalidPrivKeySize = errors.New("invalid private key size: expected 64 bytes")
)

// KeyPair holds an Ed25519 key pair used for MeshCore node identity.
type KeyPair struct {
	PublicKey  ed25519.PublicKey  // 32 bytes
	PrivateKey ed25519.PrivateKey // 64 bytes
}

// GenerateKeyPair generates a new Ed25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	return &KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// KeyPairFromPrivateKey reconstructs a KeyPair from a 64-byte Ed25519 private key.
// The public key is extracted from the last 32 bytes of the private key (standard Go format).
func KeyPairFromPrivateKey(privKey []byte) (*KeyPair, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivKeySize
	}
	priv := ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))
	copy(priv, privKey)
	pub := priv.Public().(ed25519.PublicKey)
	return &KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// Hash returns the first byte of the public key, used for routing in MeshCore.
func (kp *KeyPair) Hash() uint8 {
	return kp.PublicKey[0]
}

// Ed25519PubKeyToX25519 converts an Ed25519 public key to its X25519 (Curve25519)
// equivalent. This is used for ECDH key exchange with MeshCore nodes.
func Ed25519PubKeyToX25519(edPubKey []byte) ([]byte, error) {
	point, err := new(edwards25519.Point).SetBytes(edPubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 public key: %w", err)
	}
	return point.BytesMontgomery(), nil
}

// Ed25519PrivKeyToX25519 converts an Ed25519 private key to its X25519 equivalent.
// This follows RFC 8032: SHA-512 the seed, then clamp the first 32 bytes.
func Ed25519PrivKeyToX25519(edPrivKey ed25519.PrivateKey) ([]byte, error) {
	if len(edPrivKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivKeySize
	}

	// The seed is the first 32 bytes of the Go Ed25519 private key
	seed := edPrivKey.Seed()

	// SHA-512 the seed per RFC 8032
	h := sha512.Sum512(seed)

	// Clamp: clear lowest 3 bits, clear bit 255, set bit 254
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	return h[:32], nil
}

// ComputeSharedSecret derives a shared secret from a local Ed25519 private key
// and a remote Ed25519 public key using X25519 ECDH.
// Returns a 32-byte shared secret suitable for use with EncryptAddressed/DecryptAddressed.
func ComputeSharedSecret(localPrivKey ed25519.PrivateKey, remotePubKey []byte) ([]byte, error) {
	if len(remotePubKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidPubKeySize
	}

	// Convert Ed25519 keys to X25519
	x25519Priv, err := Ed25519PrivKeyToX25519(localPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key: %w", err)
	}

	x25519Pub, err := Ed25519PubKeyToX25519(remotePubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key: %w", err)
	}

	// X25519 ECDH
	secret, err := curve25519.X25519(x25519Priv, x25519Pub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	return secret, nil
}
