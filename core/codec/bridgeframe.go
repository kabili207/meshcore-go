package codec

import (
	"encoding/binary"
	"fmt"
)

// BridgeFrameOverhead is the size of a bridge frame's magic and checksum.
const BridgeFrameOverhead = 4

// EncodeBridgeFrame wraps payload in the datagram framing the firmware's ESP-NOW
// bridge and the EastMesh MQTT bridge share.
// Frame format: [0xC03E (2 bytes BE)][checksum (2 bytes BE)][payload]
//
// Unlike an RS232 frame there is no length field, since the datagram bounds the
// frame, and the checksum comes first. Everything after the magic is XORed with
// secret, repeating. An empty secret leaves the frame in the clear.
func EncodeBridgeFrame(payload []byte, secret string) ([]byte, error) {
	if len(payload) > MaxTransUnit {
		return nil, ErrPayloadTooLarge
	}

	frame := make([]byte, BridgeFrameOverhead+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], BridgePacketMagic)
	binary.BigEndian.PutUint16(frame[2:4], Fletcher16(payload))
	copy(frame[BridgeFrameOverhead:], payload)
	xorBridgeFrame(frame[2:], secret)

	return frame, nil
}

// DecodeBridgeFrame unwraps a frame produced by EncodeBridgeFrame and returns a
// copy of its payload. A wrong secret surfaces as ErrChecksumMismatch.
func DecodeBridgeFrame(data []byte, secret string) ([]byte, error) {
	if len(data) < BridgeFrameOverhead {
		return nil, ErrFrameTooShort
	}
	if binary.BigEndian.Uint16(data[0:2]) != BridgePacketMagic {
		return nil, ErrInvalidMagic
	}
	if len(data)-BridgeFrameOverhead > MaxTransUnit {
		return nil, ErrPayloadTooLarge
	}

	body := make([]byte, len(data)-2)
	copy(body, data[2:])
	xorBridgeFrame(body, secret)

	receivedChecksum := binary.BigEndian.Uint16(body[0:2])
	payload := body[2:]
	if !ValidateChecksum(payload, receivedChecksum) {
		return nil, fmt.Errorf("%w: expected %04x, got %04x",
			ErrChecksumMismatch, Fletcher16(payload), receivedChecksum)
	}
	return payload, nil
}

func xorBridgeFrame(data []byte, secret string) {
	if secret == "" {
		return
	}
	for i := range data {
		data[i] ^= secret[i%len(secret)]
	}
}
