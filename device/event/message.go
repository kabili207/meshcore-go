package event

// TextMessageReceived fires after a TXT_MSG packet is successfully decrypted
// and parsed. An ACK has already been sent to the sender before this event
// is emitted (matching firmware behavior).
type TextMessageReceived struct {
	Event
	Reply ReplyContext

	// Message is the decrypted text content with AES-ECB padding stripped.
	Message string

	// TxtType is the message type: codec.TxtTypePlain (regular message),
	// codec.TxtTypeCLI (admin command), or codec.TxtTypeSigned (signed message).
	TxtType uint8

	// Attempt is the sender's retry attempt number (0-3). Attempt > 0
	// indicates the sender retransmitted because it did not receive an ACK.
	Attempt uint8

	// SenderPubKeyPrefix is the first 4 bytes of the sender's public key,
	// present only for signed messages (TxtType == TxtTypeSigned). Nil otherwise.
	SenderPubKeyPrefix []byte
}

// GroupTextReceived fires when an unencrypted group text message is received.
// Group messages are not addressed to a specific node and use channel-based
// shared key encryption.
type GroupTextReceived struct {
	Event

	// ChannelHash is the first byte of the SHA256 hash of the channel's
	// shared key, identifying which group channel this message belongs to.
	ChannelHash uint8

	// Message is the decrypted text content.
	Message string
}

// GroupDataReceived fires when an unencrypted group datagram is received.
// This is the binary equivalent of GroupTextReceived for arbitrary data.
type GroupDataReceived struct {
	Event

	// ChannelHash is the first byte of the SHA256 hash of the channel's
	// shared key, identifying which group channel this data belongs to.
	ChannelHash uint8

	// Data is the decrypted binary payload.
	Data []byte
}
