package event

// PathReceived fires when a PATH packet is decrypted and its routing
// information has been applied to the contact store.
//
// If the PATH bundles a known inner payload type (e.g., ACK or RESPONSE),
// the node emits the appropriate inner event (AckReceived, ResponseReceived)
// instead of PathReceived. This event only fires for PATH packets with
// unknown or unhandled inner types.
type PathReceived struct {
	Event
	Reply ReplyContext

	// ReturnPath is the path data from the PATH content, representing
	// the route back to the sender.
	ReturnPath []byte

	// InnerType is the payload type of the bundled content (e.g.,
	// codec.PayloadTypeAck, codec.PayloadTypeResponse).
	InnerType uint8

	// InnerData is the raw bundled content. For known types this has
	// already been processed and the corresponding event emitted instead.
	InnerData []byte
}

// TraceReceived fires when a TRACE packet completes its route and returns to
// this node (the trace initiator). It carries the per-hop signal quality
// collected along the traced path.
type TraceReceived struct {
	Event

	// Tag is the trace's unique identifier, matching the SendTrace tag.
	Tag uint32

	// Flags is the trace flags byte (lower 2 bits encode the relay hash size).
	Flags uint8

	// SNRs are the per-hop signal-to-noise values (raw, multiply by 0.25 for
	// dB), in route order.
	SNRs []int8

	// PathHashes are the relay hashes of the traced route.
	PathHashes []byte
}
