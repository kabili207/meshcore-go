package acl

import (
	"github.com/kabili207/meshcore-go/core/codec"
)

// Reject is returned by Authenticator.Resolve when no permission should be
// granted (no matching password and no open access).
const Reject = -1

// Authenticator resolves a login password to a permission role. It is
// configured per role because the mapping differs: a repeater grants GUEST for
// its guest password and rejects unknown passwords, while a room server grants
// READ_WRITE for its guest password and can fall back to open (guest) access.
type Authenticator struct {
	// AdminPassword grants PermACLAdmin when matched. Empty disables.
	AdminPassword string

	// GuestPassword grants GuestPerms when matched. Empty disables.
	GuestPassword string

	// GuestPerms is the role granted for a correct guest password.
	GuestPerms uint8

	// AllowOpen lets an unrecognized password through with OpenPerms.
	AllowOpen bool

	// OpenPerms is the role granted for open access when AllowOpen is set.
	OpenPerms uint8
}

// Resolve returns the permission to grant, or Reject (-1) to deny. existingPerms
// is the current permission of a known client, or Reject if the client is new.
// A blank password from a known client keeps its existing permission (re-login).
func (a Authenticator) Resolve(existingPerms int, password string) int {
	if existingPerms != Reject && password == "" {
		return existingPerms
	}
	if a.AdminPassword != "" && password == a.AdminPassword {
		return int(codec.PermACLAdmin)
	}
	if a.GuestPassword != "" && password == a.GuestPassword {
		return int(a.GuestPerms)
	}
	if a.AllowOpen {
		return int(a.OpenPerms)
	}
	return Reject
}
