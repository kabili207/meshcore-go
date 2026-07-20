package serial

import (
	"bytes"
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

// ParseSendTracePath parses a CMD_SEND_TRACE_PATH frame:
// [code][tag u32][auth u32][flags u8][path]. path is the concatenated relay
// hashes; it aliases the payload.
func ParseSendTracePath(payload []byte) (tag, authCode uint32, flags uint8, path []byte, err error) {
	if len(payload) <= 10 || payload[0] != CmdSendTracePath {
		return 0, 0, 0, nil, ErrShortFrame
	}
	tag = binary.LittleEndian.Uint32(payload[1:5])
	authCode = binary.LittleEndian.Uint32(payload[5:9])
	flags = payload[9]
	path = payload[10:]
	return tag, authCode, flags, path, nil
}

// RadioParams is a parsed CMD_SET_RADIO_PARAMS frame. Freq is in kHz
// (freq_MHz*1000) and Bw in Hz (bw_kHz*1000), matching SELF_INFO.
type RadioParams struct {
	Freq uint32
	Bw   uint32
	SF   uint8
	CR   uint8
}

// ParseSetRadioParams parses a CMD_SET_RADIO_PARAMS frame:
// [code][freq u32][bw u32][sf u8][cr u8][repeat u8?]. The optional repeat byte
// (a repeater feature) is ignored.
func ParseSetRadioParams(payload []byte) (*RadioParams, error) {
	if len(payload) < 1+4+4+1+1 || payload[0] != CmdSetRadioParams {
		return nil, ErrShortFrame
	}
	return &RadioParams{
		Freq: binary.LittleEndian.Uint32(payload[1:5]),
		Bw:   binary.LittleEndian.Uint32(payload[5:9]),
		SF:   payload[9],
		CR:   payload[10],
	}, nil
}

// ParseSetTxPower reads the signed tx power (dBm) from a CMD_SET_RADIO_TX_POWER frame.
func ParseSetTxPower(payload []byte) (int8, error) {
	if len(payload) < 2 || payload[0] != CmdSetRadioTxPower {
		return 0, ErrShortFrame
	}
	return int8(payload[1]), nil
}

// ParseSetTuningParams reads rx-delay and airtime-factor (both x1000) from a
// CMD_SET_TUNING_PARAMS frame.
func ParseSetTuningParams(payload []byte) (rxDelay, airtimeFactor uint32, err error) {
	if len(payload) < 1+4+4 || payload[0] != CmdSetTuningParams {
		return 0, 0, ErrShortFrame
	}
	return binary.LittleEndian.Uint32(payload[1:5]), binary.LittleEndian.Uint32(payload[5:9]), nil
}

// ParseSetAutoaddConfig parses a CMD_SET_AUTOADD_CONFIG frame:
// [code][config][max_hops?]. hasMaxHops is false when the optional max-hops byte
// is absent; when present it is clamped to 64, matching the firmware.
func ParseSetAutoaddConfig(payload []byte) (config, maxHops uint8, hasMaxHops bool, err error) {
	if len(payload) < 2 || payload[0] != CmdSetAutoaddConfig {
		return 0, 0, false, ErrShortFrame
	}
	config = payload[1]
	if len(payload) >= 3 {
		maxHops = min(payload[2], 64)
		hasMaxHops = true
	}
	return config, maxHops, hasMaxHops, nil
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

// contactFixedLen is the fixed prefix of a CMD_ADD_UPDATE_CONTACT frame through
// last_advert (code + pubkey + type + flags + out_path_len + out_path + name +
// last_advert). GPS and lastmod are optional trailing fields.
const contactFixedLen = 1 + 32 + 1 + 1 + 1 + 64 + 32 + 4 // 136

// ParseContact parses a CMD_ADD_UPDATE_CONTACT frame into a Contact. It shares
// the RESP_CODE_CONTACT layout. GPSLat/GPSLon (offset 136) and LastMod (offset
// 144) are read only when present; LastMod is left 0 when absent so the caller
// can substitute its own clock, as the firmware does.
func ParseContact(payload []byte) (*Contact, error) {
	if len(payload) < contactFixedLen {
		return nil, ErrShortFrame
	}
	c := &Contact{
		Type:       payload[33],
		Flags:      payload[34],
		OutPathLen: payload[35],
		Name:       cString(payload[100:132]),
		LastAdvert: binary.LittleEndian.Uint32(payload[132:136]),
	}
	copy(c.PublicKey[:], payload[1:33])
	if c.OutPathLen != PathLenUnknown && int(c.OutPathLen) <= 64 {
		c.OutPath = append([]byte(nil), payload[36:36+int(c.OutPathLen)]...)
	}
	if len(payload) >= contactFixedLen+8 {
		c.GPSLat = int32(binary.LittleEndian.Uint32(payload[136:140]))
		c.GPSLon = int32(binary.LittleEndian.Uint32(payload[140:144]))
		if len(payload) >= contactFixedLen+12 {
			c.LastMod = binary.LittleEndian.Uint32(payload[144:148])
		}
	}
	return c, nil
}

// cString reads a NUL-terminated string from a fixed-width field.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// ParseGetChannel reads the channel index from a CMD_GET_CHANNEL frame.
func ParseGetChannel(payload []byte) (index uint8, err error) {
	if len(payload) < 2 || payload[0] != CmdGetChannel {
		return 0, ErrShortFrame
	}
	return payload[1], nil
}

// setChannelLen is a CMD_SET_CHANNEL frame with a 128-bit secret:
// code + index + name(32) + secret(16).
const setChannelLen = 1 + 1 + 32 + 16 // 50

// SetChannel256Len is the frame length of a 256-bit-secret CMD_SET_CHANNEL,
// which the firmware rejects as unsupported.
const SetChannel256Len = 1 + 1 + 32 + 32 // 66

// ParseSetChannel parses a CMD_SET_CHANNEL frame ([code][index][name 32-byte
// C-string][secret 16]). Only the 128-bit secret form is supported; the caller
// should reject a frame of SetChannel256Len or longer as unsupported first. The
// returned secret is a fresh 16-byte copy.
func ParseSetChannel(payload []byte) (index uint8, name string, secret []byte, err error) {
	if len(payload) < setChannelLen || payload[0] != CmdSetChannel {
		return 0, "", nil, ErrShortFrame
	}
	index = payload[1]
	name = cString(payload[2:34])
	secret = append([]byte(nil), payload[34:50]...)
	return index, name, secret, nil
}

// ParseSetAdvertName reads the new node name from a CMD_SET_ADVERT_NAME frame.
// The name is the remainder of the frame (not NUL-terminated on the wire).
func ParseSetAdvertName(payload []byte) (name string, err error) {
	if len(payload) < 2 || payload[0] != CmdSetAdvertName {
		return "", ErrShortFrame
	}
	return string(payload[1:]), nil
}
