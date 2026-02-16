package crypto

import (
	"fmt"

	"filippo.io/edwards25519"
)

// Ed25519PubKeyToX25519 converts an Ed25519 public key to its X25519 (Curve25519)
// equivalent. This is used for ECDH key exchange with MeshCore nodes, which use
// Ed25519 keys for identity but need X25519 keys for encryption.
func Ed25519PubKeyToX25519(edPubKey []byte) ([]byte, error) {
	point, err := new(edwards25519.Point).SetBytes(edPubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 public key: %w", err)
	}
	return point.BytesMontgomery(), nil
}
