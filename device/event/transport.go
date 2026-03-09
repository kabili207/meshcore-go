package event

import (
	"github.com/kabili207/meshcore-go/transport"
)

// TransportStateChanged fires when a transport's connection state changes.
// This is emitted for connect, disconnect, reconnect, and error events.
type TransportStateChanged struct {
	// TransportName identifies which transport changed state (e.g., "mqtt", "serial").
	TransportName string

	// State is the new transport state.
	State transport.Event
}
