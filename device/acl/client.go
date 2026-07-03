// Package acl provides access-control-list primitives shared by node roles that
// authenticate peers and gate actions by permission (the room server and the
// repeater). It holds the generic client model, an in-memory store, and a
// password authenticator. Role-specific session state is layered on top by
// embedding Client.
package acl

import (
	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
)

// PathUnknown marks an OutPathLen with no known direct route (firmware
// OUT_PATH_UNKNOWN).
const PathUnknown uint8 = 0xFF

// Client is an authenticated peer in an access-control list: it has proven a
// password and been granted a permission role. This is the generic ACL state
// shared across roles; role-specific state (e.g. the room server's post-sync
// fields) is added by embedding Client in a wrapper struct.
//
// Mirrors the generic (non-union) portion of the firmware's ClientInfo in
// helpers/ClientACL.h.
type Client struct {
	// Identity
	ID   core.MeshCoreID // Ed25519 public key (32 bytes)
	Name string

	// Permissions — lower 2 bits are the ACL role (codec.PermACLRoleMask).
	Permissions uint8

	// Routing
	OutPathLen uint8  // PathUnknown (0xFF) = no known direct route
	OutPath    []byte // direct routing path

	// Timestamps
	LastTimestamp uint32 // peer's clock (from their messages) — for replay detection
	LastActivity  uint32 // our clock — for keep-alive / eviction
}

// Role returns the client's ACL role (lower 2 bits of Permissions).
func (c *Client) Role() uint8 {
	return c.Permissions & codec.PermACLRoleMask
}

// IsAdmin reports whether the client has admin permissions.
func (c *Client) IsAdmin() bool {
	return c.Role() == codec.PermACLAdmin
}

// IsGuest reports whether the client has guest (temporary) permissions.
func (c *Client) IsGuest() bool {
	return c.Role() == codec.PermACLGuest
}

// CanWrite reports whether the client may post messages (ReadWrite or Admin).
func (c *Client) CanWrite() bool {
	return c.Role() >= codec.PermACLReadWrite
}

// CanRead reports whether the client may receive messages (any role above Guest).
func (c *Client) CanRead() bool {
	return c.Role() >= codec.PermACLReadOnly
}
