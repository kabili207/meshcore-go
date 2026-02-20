package room

import (
	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
)

// ClientInfo represents a connected client on a room server.
// This is server-side session state — distinct from contact.ContactInfo which
// tracks discovered peers.
//
// This mirrors the firmware's ClientInfo struct in helpers/ClientACL.h.
type ClientInfo struct {
	// Identity
	ID   core.MeshCoreID // Ed25519 public key (32 bytes)
	Name string

	// Permissions — lower 2 bits are the ACL role (codec.PermACLRoleMask).
	Permissions uint8

	// Routing
	OutPathLen int8   // -1 = unknown, >=0 = direct path length
	OutPath    []byte // direct routing path

	// Timestamps
	LastTimestamp uint32 // client's clock (from their messages)
	LastActivity  uint32 // room's clock (for keep-alive / eviction)

	// Sync tracking (used by the post sync loop)
	SyncSince         uint32 // sync messages since this timestamp (room's clock)
	PushPostTimestamp uint32 // timestamp of last pushed post
	PushFailures      uint8  // consecutive failed push attempts
}

// Role returns the client's ACL role (lower 2 bits of Permissions).
func (c *ClientInfo) Role() uint8 {
	return c.Permissions & codec.PermACLRoleMask
}

// IsAdmin returns true if the client has admin permissions.
func (c *ClientInfo) IsAdmin() bool {
	return c.Role() == codec.PermACLAdmin
}

// IsGuest returns true if the client has guest (temporary) permissions.
func (c *ClientInfo) IsGuest() bool {
	return c.Role() == codec.PermACLGuest
}

// CanWrite returns true if the client can post messages (ReadWrite or Admin).
func (c *ClientInfo) CanWrite() bool {
	return c.Role() >= codec.PermACLReadWrite
}

// CanRead returns true if the client can receive messages (any role except Guest).
func (c *ClientInfo) CanRead() bool {
	return c.Role() >= codec.PermACLReadOnly
}
