package serial

// Frame-size constants for the companion serial protocol.
//
// These mirror the firmware's companion_radio serial interface, over which the
// host (phone app) and the node exchange command frames. When the firmware bumps
// MAX_FRAME_SIZE, update MaxFrameSize here and the derived limits follow.
//
// Do not confuse MaxFrameSize with the on-air mesh transport unit. Firmware's
// MAX_TRANS_UNIT (255; see codec.MaxTransUnit = 256, the +1 buffer) bounds a full
// LoRa packet, while MaxFrameSize bounds a single host<->node serial frame and is
// much smaller. Conflating the two is what produced the earlier 247-byte
// MaxChannelDataLength (256 - 9 instead of MAX_FRAME_SIZE - 9).
const (
	// MaxFrameSize is the firmware MAX_FRAME_SIZE (BaseSerialInterface.h): the
	// maximum size of a single companion serial frame. The node's receive buffer
	// is exactly this size, so larger frames cannot be received.
	// v1.16: 176 (was 172; +4 for region transport codes).
	MaxFrameSize = 176

	// ChannelDataOverhead is the per-frame header overhead for CMD_SEND_CHANNEL_DATA.
	// Firmware: MAX_CHANNEL_DATA_LENGTH = MAX_FRAME_SIZE - 9.
	ChannelDataOverhead = 9

	// MaxChannelDataLength is the maximum payload for CMD_SEND_CHANNEL_DATA.
	// The firmware rejects channel data longer than this (MyMesh.cpp).
	MaxChannelDataLength = MaxFrameSize - ChannelDataOverhead // 167

	// FrameHeaderSize is the size of the command frame header (cmd byte).
	FrameHeaderSize = 1
)
