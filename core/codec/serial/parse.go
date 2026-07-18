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

// TxtMsgRequest is a parsed CMD_SEND_TXT_MSG frame.
type TxtMsgRequest struct {
	TxtType    uint8
	Attempt    uint8
	SenderTS   uint32
	DestPrefix []byte // first 6 bytes of the recipient's public key
	Text       string
}

// ParseSendTxtMsg parses a CMD_SEND_TXT_MSG frame:
// [code][txt_type][attempt][sender_ts u32][dest_prefix 6][text]. DestPrefix
// aliases the payload, so copy it if retained past the call.
func ParseSendTxtMsg(payload []byte) (*TxtMsgRequest, error) {
	if len(payload) < 13 || payload[0] != CmdSendTxtMsg {
		return nil, ErrShortFrame
	}
	return &TxtMsgRequest{
		TxtType:    payload[1],
		Attempt:    payload[2],
		SenderTS:   binary.LittleEndian.Uint32(payload[3:7]),
		DestPrefix: payload[7:13],
		Text:       string(payload[13:]),
	}, nil
}

// ChannelTxtMsgRequest is a parsed CMD_SEND_CHANNEL_TXT_MSG frame.
type ChannelTxtMsgRequest struct {
	TxtType    uint8
	ChannelIdx uint8
	SenderTS   uint32
	Text       string
}

// ParseSendChannelTxtMsg parses a CMD_SEND_CHANNEL_TXT_MSG frame:
// [code][txt_type][channel_idx][sender_ts u32][text].
func ParseSendChannelTxtMsg(payload []byte) (*ChannelTxtMsgRequest, error) {
	if len(payload) < 7 || payload[0] != CmdSendChannelTxtMsg {
		return nil, ErrShortFrame
	}
	return &ChannelTxtMsgRequest{
		TxtType:    payload[1],
		ChannelIdx: payload[2],
		SenderTS:   binary.LittleEndian.Uint32(payload[3:7]),
		Text:       string(payload[7:]),
	}, nil
}

// ParseGetChannel reads the channel index from a CMD_GET_CHANNEL frame.
func ParseGetChannel(payload []byte) (index uint8, err error) {
	if len(payload) < 2 || payload[0] != CmdGetChannel {
		return 0, ErrShortFrame
	}
	return payload[1], nil
}

// ParseSetAdvertName reads the new node name from a CMD_SET_ADVERT_NAME frame.
// The name is the remainder of the frame (not NUL-terminated on the wire).
func ParseSetAdvertName(payload []byte) (name string, err error) {
	if len(payload) < 2 || payload[0] != CmdSetAdvertName {
		return "", ErrShortFrame
	}
	return string(payload[1:]), nil
}
