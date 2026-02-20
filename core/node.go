package core

import (
	"encoding/hex"
	"fmt"
)

// MeshCoreID represents a MeshCore node's 32-byte Ed25519 public key.
type MeshCoreID [32]byte

// String returns the hex-encoded representation of the MeshCore ID.
func (m MeshCoreID) String() string {
	return hex.EncodeToString(m[:])
}

// Hash returns the first byte of the public key, used as a V1 path hash
// for routing in MeshCore packets.
func (m MeshCoreID) Hash() uint8 {
	return m[0]
}

// Bytes returns the underlying byte slice.
func (m MeshCoreID) Bytes() []byte {
	return m[:]
}

// IsZero returns true if the ID is all zeros (uninitialized).
func (m MeshCoreID) IsZero() bool {
	for _, b := range m {
		if b != 0 {
			return false
		}
	}
	return true
}

// IsHashMatch returns true if the first len(hash) bytes of the public key
// match the provided hash bytes. This supports variable-size hash matching
// used by TRACE packets (1, 2, 4, or 8 bytes depending on flags).
func (m MeshCoreID) IsHashMatch(hash []byte) bool {
	if len(hash) == 0 || len(hash) > len(m) {
		return false
	}
	for i, b := range hash {
		if m[i] != b {
			return false
		}
	}
	return true
}

// ParseMeshCoreID parses a hex-encoded string into a MeshCoreID.
func ParseMeshCoreID(s string) (MeshCoreID, error) {
	var id MeshCoreID
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("invalid hex string: %w", err)
	}
	if len(bytes) != 32 {
		return id, fmt.Errorf("invalid length: expected 32 bytes, got %d", len(bytes))
	}
	copy(id[:], bytes)
	return id, nil
}
