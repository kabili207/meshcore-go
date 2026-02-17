package codec

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// BridgePacketMagic is the magic number that starts every RS232 frame.
	BridgePacketMagic uint16 = 0xC03E
	// MaxTransUnit is the maximum payload size in an RS232 frame (MAX_TRANS_UNIT + 1).
	MaxTransUnit = 256
	// FrameHeaderSize is the size of the RS232 frame header (magic 2 + length 2).
	FrameHeaderSize = 4
	// FrameChecksumSize is the size of the checksum at the end of a frame.
	FrameChecksumSize = 2
	// MinFrameSize is the minimum valid frame size (header + checksum).
	MinFrameSize = FrameHeaderSize + FrameChecksumSize
)

var (
	ErrFrameTooShort    = errors.New("frame too short")
	ErrInvalidMagic     = errors.New("invalid frame magic")
	ErrPayloadTooLarge  = errors.New("payload exceeds maximum size")
	ErrChecksumMismatch = errors.New("checksum mismatch")
	ErrIncompleteFrame  = errors.New("incomplete frame")
)

// RS232Frame represents a decoded RS232 frame from a MeshCore bridge.
type RS232Frame struct {
	Payload []byte
}

// DecodeRS232Frame decodes an RS232 frame from the given data.
// Returns the decoded frame, any remaining bytes after the frame, and an error if decoding failed.
// Frame format: [0xC03E (2 bytes BE)][length (2 bytes BE)][payload (length bytes)][checksum (2 bytes BE)]
func DecodeRS232Frame(data []byte) (*RS232Frame, []byte, error) {
	if len(data) < MinFrameSize {
		return nil, data, ErrFrameTooShort
	}

	// Check magic number (big endian)
	magic := binary.BigEndian.Uint16(data[0:2])
	if magic != BridgePacketMagic {
		return nil, data, ErrInvalidMagic
	}

	// Get payload length (big endian, 2 bytes)
	payloadLen := int(binary.BigEndian.Uint16(data[2:4]))
	if payloadLen > MaxTransUnit {
		return nil, data, ErrPayloadTooLarge
	}

	// Calculate total frame size
	totalFrameSize := FrameHeaderSize + payloadLen + FrameChecksumSize
	if len(data) < totalFrameSize {
		return nil, data, ErrIncompleteFrame
	}

	// Extract payload
	payload := data[FrameHeaderSize : FrameHeaderSize+payloadLen]

	// Extract and validate checksum (big endian)
	checksumOffset := FrameHeaderSize + payloadLen
	receivedChecksum := binary.BigEndian.Uint16(data[checksumOffset : checksumOffset+2])
	if !ValidateChecksum(payload, receivedChecksum) {
		return nil, data, fmt.Errorf("%w: expected %04x, got %04x",
			ErrChecksumMismatch, Fletcher16(payload), receivedChecksum)
	}

	frame := &RS232Frame{
		Payload: make([]byte, payloadLen),
	}
	copy(frame.Payload, payload)

	// Return remaining bytes after this frame
	remaining := data[totalFrameSize:]
	return frame, remaining, nil
}

// EncodeRS232Frame encodes payload into an RS232 frame.
// Frame format: [0xC03E (2 bytes BE)][length (2 bytes BE)][payload][checksum (2 bytes BE)]
func EncodeRS232Frame(payload []byte) ([]byte, error) {
	if len(payload) > MaxTransUnit {
		return nil, ErrPayloadTooLarge
	}

	frameSize := FrameHeaderSize + len(payload) + FrameChecksumSize
	frame := make([]byte, frameSize)

	// Magic number (big endian)
	binary.BigEndian.PutUint16(frame[0:2], BridgePacketMagic)

	// Payload length (big endian, 2 bytes)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(payload)))

	// Copy payload
	copy(frame[FrameHeaderSize:], payload)

	// Calculate and append checksum (big endian)
	checksum := Fletcher16(payload)
	checksumOffset := FrameHeaderSize + len(payload)
	binary.BigEndian.PutUint16(frame[checksumOffset:], checksum)

	return frame, nil
}
