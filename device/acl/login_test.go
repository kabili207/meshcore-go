package acl

import (
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
)

func TestAuthenticator_Repeater(t *testing.T) {
	// Repeater mapping: admin/guest passwords, no open access.
	a := Authenticator{
		AdminPassword: "admin",
		GuestPassword: "guest",
		GuestPerms:    codec.PermACLGuest,
	}

	tests := []struct {
		name     string
		existing int
		password string
		want     int
	}{
		{"admin password", Reject, "admin", codec.PermACLAdmin},
		{"guest password", Reject, "guest", codec.PermACLGuest},
		{"wrong password", Reject, "nope", Reject},
		{"blank, unknown client", Reject, "", Reject},
		{"blank, known client keeps perms", codec.PermACLAdmin, "", codec.PermACLAdmin},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.Resolve(tt.existing, tt.password); got != tt.want {
				t.Errorf("Resolve(%d, %q) = %d, want %d", tt.existing, tt.password, got, tt.want)
			}
		})
	}
}

func TestAuthenticator_RoomOpen(t *testing.T) {
	// Room mapping: guest password grants ReadWrite, open access grants Guest.
	a := Authenticator{
		AdminPassword: "admin",
		GuestPassword: "guest",
		GuestPerms:    codec.PermACLReadWrite,
		AllowOpen:     true,
		OpenPerms:     codec.PermACLGuest,
	}

	if got := a.Resolve(Reject, "guest"); got != codec.PermACLReadWrite {
		t.Errorf("guest password = %d, want ReadWrite", got)
	}
	if got := a.Resolve(Reject, "anything"); got != codec.PermACLGuest {
		t.Errorf("open access = %d, want Guest", got)
	}
}
