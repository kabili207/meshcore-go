package event

import (
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/contact"
)

// AdvertReceived fires when a valid, non-replay ADVERT packet is processed.
// The contact store is already updated before this event is emitted — the
// Contact field points to the stored (or newly created) contact entry.
type AdvertReceived struct {
	Event

	// Advert is the parsed advertisement payload, including the sender's
	// public key, timestamp, signature, and optional app data (name, node
	// type, location).
	Advert *codec.AdvertPayload

	// Contact is the contact entry that was created or updated from this
	// advert. This is the actual stored pointer from the contact store.
	Contact *contact.ContactInfo

	// IsNew is true if this is the first time this peer has been seen
	// (a new contact was created), false if an existing contact was updated.
	IsNew bool
}
