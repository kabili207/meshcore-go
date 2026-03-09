// Package event provides typed event definitions for MeshCore node packet processing.
//
// Events are emitted by node types (CompanionNode, RoomNode, RepeaterNode) after
// decrypting and parsing incoming packets. Consumers register handlers via OnEvent
// and type-switch on the concrete event type:
//
//	node.OnEvent(func(evt any) {
//	    switch e := evt.(type) {
//	    case *event.TextMessageReceived:
//	        fmt.Println("Message from", e.From, ":", e.Message)
//	    case *event.AdvertReceived:
//	        fmt.Println("Discovered", e.Contact.Name)
//	    }
//	})
//
// Events carry fully decoded, plaintext data. The node handles all protocol
// mechanics (decryption, signature verification, ACK sending, contact updates)
// before emitting events.
package event

import (
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
)

// Handler is the callback signature for event consumers. Handlers receive
// a pointer to a concrete event type and should type-switch to handle it.
// Handlers are called synchronously — long-running work should be dispatched
// to a goroutine.
type Handler func(evt any)

// Event is the base struct embedded in all concrete event types. It carries
// metadata common to every received packet.
type Event struct {
	// From is the sender's full MeshCoreID (32-byte Ed25519 public key),
	// resolved from the packet's source hash.
	From core.MeshCoreID

	// Timestamp is when the packet was received. For text messages, this
	// is the sender's timestamp from the message content; otherwise it is
	// the local receive time.
	Timestamp time.Time

	// RawPacket is the original packet before decoding. Provided for
	// advanced consumers that need access to routing metadata (path,
	// route type, transport codes, SNR). May be nil for synthetic events.
	RawPacket *codec.Packet

	// Source indicates which transport the packet arrived on.
	Source transport.PacketSource
}

// ReplyContext carries the cryptographic and routing state needed to send
// an encrypted response to the sender of an addressed packet. It is
// populated by the node during decryption and included in events that
// originate from addressed payloads.
type ReplyContext struct {
	// SharedSecret is the pre-computed ECDH shared secret between this
	// node and the sender. Used for encrypting response payloads.
	SharedSecret []byte

	// FloodPath is the reversed flood path from the original packet.
	// Non-nil only when the original packet arrived via flood routing.
	// Used by SendReply to wrap responses in PATH packets (matching
	// firmware room server behavior).
	FloodPath []byte

	// DirectPath is the contact's stored direct routing path, if known.
	// May be nil if no direct path has been established.
	DirectPath []byte

	// DirectPathLen is the length of the direct path. Set to -1 when
	// no direct path is known (flood-only contact).
	DirectPathLen int8
}

// HasFloodPath returns true if the original packet arrived via flood routing
// and a reversed path is available for PATH-wrapped responses.
func (r *ReplyContext) HasFloodPath() bool {
	return len(r.FloodPath) > 0
}

// HasDirectPath returns true if a direct routing path to the sender is known.
func (r *ReplyContext) HasDirectPath() bool {
	return r.DirectPathLen >= 0 && len(r.DirectPath) > 0
}
