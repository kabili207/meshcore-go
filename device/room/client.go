package room

import (
	"github.com/kabili207/meshcore-go/device/acl"
)

// ClientInfo is a room server's per-client session state: an authenticated ACL
// client (acl.Client, providing identity, permissions, routing, and the role
// helpers Role/IsAdmin/IsGuest/CanWrite/CanRead) plus room-specific post-sync
// fields.
//
// This mirrors the firmware's ClientInfo (helpers/ClientACL.h), whose generic
// fields sit alongside a role-specific union.
type ClientInfo struct {
	acl.Client

	// Sync tracking (used by the post sync loop)
	SyncSince         uint32 // sync messages since this timestamp (room's clock)
	PushPostTimestamp uint32 // timestamp of last pushed post
	PushFailures      uint8  // consecutive failed push attempts
}
