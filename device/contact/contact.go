// Package contact provides contact/peer management for MeshCore networks.
//
// A ContactInfo represents a known peer with its identity, routing information,
// and cached ECDH shared secret. The ContactManager stores and manages contacts
// with firmware-compatible eviction and lookup semantics.
//
// This corresponds to the firmware's ContactInfo struct (helpers/ContactInfo.h)
// and contact operations in BaseChatMesh (helpers/BaseChatMesh.cpp).
package contact

import (
	"crypto/ed25519"
	"sync"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/crypto"
)

const (
	// MaxNameLen is the maximum contact name length (firmware: char[32]).
	MaxNameLen = 32

	// FlagFavorite marks a contact as a favorite. Favorites are never evicted
	// when the contact list is full.
	FlagFavorite = 0x01

	// PathUnknown is the sentinel value for OutPathLen when no direct routing
	// path is known. The contact can only be reached via flood routing.
	PathUnknown int8 = -1
)

// ContactInfo represents a known peer in the mesh network.
// This mirrors the firmware's ContactInfo struct in helpers/ContactInfo.h.
type ContactInfo struct {
	// Identity
	ID   core.MeshCoreID // Ed25519 public key (32 bytes)
	Name string          // Node name (up to MaxNameLen chars)
	Type uint8           // Node type: codec.NodeTypeChat, NodeTypeRepeater, etc.

	// Flags and routing
	Flags      uint8  // Bit 0 = favorite (FlagFavorite); other bits reserved
	OutPathLen int8   // -1 = unknown (flood only), >=0 = direct path length
	OutPath    []byte // Direct routing path (up to codec.MaxPathSize bytes)

	// Timestamps
	LastAdvertTimestamp uint32 // Peer's clock timestamp from their last ADVERT
	LastMod            uint32 // Our clock time when contact was last modified

	// Location (stored as integer × 1,000,000, matching firmware int32)
	GPSLat int32
	GPSLon int32

	// Sync tracking
	SyncSince uint32

	// Shared secret cache (lazy ECDH, protected by its own mutex)
	mu                sync.Mutex
	sharedSecret      [32]byte
	sharedSecretValid bool
}

// IsFavorite returns true if the contact is marked as a favorite.
// Favorite contacts are never evicted when the contact list is full.
func (c *ContactInfo) IsFavorite() bool {
	return c.Flags&FlagFavorite != 0
}

// SetFavorite sets or clears the favorite flag.
func (c *ContactInfo) SetFavorite(fav bool) {
	if fav {
		c.Flags |= FlagFavorite
	} else {
		c.Flags &^= FlagFavorite
	}
}

// HasDirectPath returns true if a direct routing path is known for this contact.
func (c *ContactInfo) HasDirectPath() bool {
	return c.OutPathLen >= 0
}

// GetSharedSecret lazily computes and caches the ECDH shared secret between
// the local node's private key and this contact's public key. Thread-safe.
//
// The secret is computed via X25519 ECDH (Ed25519 keys transposed to X25519)
// and cached for subsequent calls. Use InvalidateSharedSecret to force
// recomputation.
func (c *ContactInfo) GetSharedSecret(localPrivKey ed25519.PrivateKey) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sharedSecretValid {
		return c.sharedSecret[:], nil
	}

	secret, err := crypto.ComputeSharedSecret(localPrivKey, c.ID[:])
	if err != nil {
		return nil, err
	}
	copy(c.sharedSecret[:], secret)
	c.sharedSecretValid = true
	return c.sharedSecret[:], nil
}

// InvalidateSharedSecret marks the cached shared secret as stale,
// forcing recomputation on the next GetSharedSecret call.
func (c *ContactInfo) InvalidateSharedSecret() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sharedSecretValid = false
}
