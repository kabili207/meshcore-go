package room

import (
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/acl"
)

const (
	// loginDataMinSize is the minimum decrypted ANON_REQ data size for login:
	// timestamp(4) + sync_since(4) + password(at least 1 null byte).
	loginDataMinSize = 9

	// loginResponseSize is the size of the login response content.
	// timestamp(4) + resp_type(1) + legacy(1) + admin_flag(1) + perms(1) + random(4) + version(1)
	loginResponseSize = 13

	// FirmwareVersion is the protocol version reported in login responses.
	FirmwareVersion = 0x01
)

// resolvePermissions determines what permission level to grant for a login.
// Returns -1 (acl.Reject) if no permission should be granted.
//
// Room mapping: admin password -> Admin, guest password -> ReadWrite, and an
// open room (AllowReadOnly) grants Guest. Firmware assigns PERM_ACL_GUEST for
// allow_read_only logins, and guests are blocked from posting; granting ReadOnly
// would let open-room users post (only guests are gated in HandleTextMessage).
func (s *Server) resolvePermissions(existing *ClientInfo, password string) int {
	existingPerms := acl.Reject
	if existing != nil {
		existingPerms = int(existing.Permissions)
	}
	return acl.Authenticator{
		AdminPassword: s.cfg.AdminPassword,
		GuestPassword: s.cfg.GuestPassword,
		GuestPerms:    codec.PermACLReadWrite,
		AllowOpen:     s.cfg.AllowReadOnly,
		OpenPerms:     codec.PermACLGuest,
	}.Resolve(existingPerms, password)
}

// extractNullTerminated extracts a null-terminated string from data.
func extractNullTerminated(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}
