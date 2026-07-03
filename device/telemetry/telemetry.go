// Package telemetry defines the provider interface and permission model for
// GET_TELEMETRY responses, shared by the room server and repeater. Readings are
// encoded as CayenneLPP via github.com/TheThingsNetwork/go-cayenne-lib.
package telemetry

import (
	cayennelpp "github.com/TheThingsNetwork/go-cayenne-lib"

	"github.com/kabili207/meshcore-go/core/codec"
)

// Permission mask bits (firmware TELEM_PERM_*) select which categories a
// requester may read from a GET_TELEMETRY response.
const (
	PermBase        uint8 = 0x01 // battery / base telemetry
	PermLocation    uint8 = 0x02 // GPS location
	PermEnvironment uint8 = 0x04 // environment sensors

	// ChannelSelf is the CayenneLPP data channel for the node's own readings
	// (firmware TELEM_CHANNEL_SELF).
	ChannelSelf uint8 = 1
)

// Provider populates a CayenneLPP encoder with telemetry readings, gated by the
// requester's permission mask. It mirrors firmware's SensorManager.querySensors.
// Implementations should always include base telemetry (e.g. battery voltage on
// ChannelSelf); the mask gates the optional location and environment categories.
type Provider interface {
	QuerySensors(permissions uint8, enc cayennelpp.Encoder)
}

// Mask computes the effective permission mask for a GET_TELEMETRY request.
// requestData[0] is an inverse mask the requester supplies (0 means "all"),
// matching firmware's perm_mask = ~payload[1]. Guests are restricted to base
// telemetry only (mask 0).
func Mask(requestData []byte, permissions uint8) uint8 {
	mask := uint8(0xFF)
	if len(requestData) > 0 {
		mask = ^requestData[0]
	}
	if permissions&codec.PermACLRoleMask == codec.PermACLGuest {
		mask = 0
	}
	return mask
}

// Encode runs the provider for a request and returns the CayenneLPP buffer. A
// nil provider yields an empty buffer.
func Encode(p Provider, requestData []byte, permissions uint8) []byte {
	if p == nil {
		return nil
	}
	enc := cayennelpp.NewEncoder()
	p.QuerySensors(Mask(requestData, permissions), enc)
	return enc.Bytes()
}
