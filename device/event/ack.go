package event

// AckReceived fires when an ACK packet arrives. If an ACK tracker is
// configured, the pending ACK is already resolved before this event
// is emitted.
type AckReceived struct {
	Event

	// Checksum is the 4-byte CRC that identifies which message this ACK
	// acknowledges. Computed from the original message content and the
	// sender's public key.
	Checksum uint32
}
