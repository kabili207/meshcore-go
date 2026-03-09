package event

// PacketReceived is the catch-all event for any payload type that does not
// have a more specific event type. Consumers can inspect RawPacket to
// determine the payload type and handle it manually.
type PacketReceived struct {
	Event
}
