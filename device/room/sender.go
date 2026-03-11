package room

import (
	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/device/event"
)

// NodeSender is the interface used by the room server to send responses.
// It abstracts the underlying node's encryption and routing logic so the
// room server doesn't need direct access to the router or crypto.
//
// The primary implementation is BaseNode.SendReply, exposed through
// RoomNode. The interface also supports sending to arbitrary contacts
// (for the sync loop) by constructing a ReplyContext from stored contact
// info.
type NodeSender interface {
	// SendReply sends an encrypted response using the routing context from
	// a received event. Automatically chooses direct vs flood vs PATH routing.
	SendReply(reply event.ReplyContext, to core.MeshCoreID, payloadType uint8, plaintext []byte) error

	// SendACK sends an ACK packet to the specified recipient.
	SendACK(to core.MeshCoreID, ackHash uint32)

	// SendToContact sends an encrypted packet to a contact, constructing
	// routing context from the contact store. Used by the sync loop to push
	// posts independently of received events.
	SendToContact(to core.MeshCoreID, payloadType uint8, plaintext []byte) error
}
