package serial

import (
	"encoding/binary"
	"errors"
)

// Command payload parsers for the companion protocol (app -> device). Each takes
// the full frame payload (payload[0] is the command code) and extracts the
// fields the firmware reads. Phase 1 covers the handshake, contact sync, and
// device time; message and channel commands are parsed in their own phases.

// ErrShortFrame is returned when a command frame is too short for its command.
var ErrShortFrame = errors.New("serial: command frame too short")

// ParseAppStart extracts the app name from a CMD_APP_START frame. Bytes 1..7 are
// reserved; the name is the remainder (UTF-8, not NUL-terminated on the wire).
func ParseAppStart(payload []byte) (appName string, err error) {
	if len(payload) < 8 || payload[0] != CmdAppStart {
		return "", ErrShortFrame
	}
	return string(payload[8:]), nil
}

// ParseDeviceQuery extracts the app's declared protocol version from a
// CMD_DEVICE_QUERY frame. The server must remember it: it selects the V3 vs
// pre-V3 message layout for incoming-message frames.
func ParseDeviceQuery(payload []byte) (appTargetVer uint8, err error) {
	if len(payload) < 2 || payload[0] != CmdDeviceQuery {
		return 0, ErrShortFrame
	}
	return payload[1], nil
}

// ParseGetContactsSince reads the optional "since" filter from a CMD_GET_CONTACTS
// frame. hasSince is false for a bare request (send all contacts); when true,
// only contacts whose LastMod is newer than since should be streamed.
func ParseGetContactsSince(payload []byte) (since uint32, hasSince bool) {
	if len(payload) >= 5 {
		return binary.LittleEndian.Uint32(payload[1:5]), true
	}
	return 0, false
}

// ParseSetDeviceTime reads the epoch seconds from a CMD_SET_DEVICE_TIME frame.
// The firmware only accepts a time at or after its current clock.
func ParseSetDeviceTime(payload []byte) (epochSecs uint32, err error) {
	if len(payload) < 5 || payload[0] != CmdSetDeviceTime {
		return 0, ErrShortFrame
	}
	return binary.LittleEndian.Uint32(payload[1:5]), nil
}
