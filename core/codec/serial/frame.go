package serial

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// Companion transport framing.
//
// The host (phone app) and node exchange frames over a byte stream (USB serial,
// a pty, or TCP). A frame is a 3-byte header followed by the payload:
//
//	[0]    marker: FrameAppToNode (0x3c) or FrameNodeToApp (0x3e)
//	[1..2] payload length, uint16 little-endian, counting payload bytes only
//	[3..]  payload; payload[0] is the command/response/push code
//
// There is no checksum and no terminator; frame boundaries come solely from the
// length field. This framing is identical on serial and TCP. It is distinct
// from the on-air RS232 radio bridge in core/codec/rs232.go, which carries whole
// mesh packets with Fletcher-16 checksums, not companion frames.
//
// Over BLE the firmware drops the 3-byte header entirely (the GATT packet
// boundary is the frame); this package does not implement BLE.
const (
	// FrameAppToNode marks a frame the host sends the node (a command).
	FrameAppToNode = 0x3c
	// FrameNodeToApp marks a frame the node sends the host (a response or push).
	FrameNodeToApp = 0x3e

	// frameHeaderLen is the marker byte plus the 2-byte length field.
	frameHeaderLen = 3
)

// EncodeFrame wraps payload in a companion frame with the given marker (normally
// FrameNodeToApp from a server). It errors if the payload exceeds MaxFrameSize,
// which the firmware's receive buffer cannot hold.
func EncodeFrame(marker byte, payload []byte) ([]byte, error) {
	if len(payload) > MaxFrameSize {
		return nil, fmt.Errorf("serial: frame payload %d exceeds MaxFrameSize %d", len(payload), MaxFrameSize)
	}
	buf := make([]byte, frameHeaderLen+len(payload))
	buf[0] = marker
	binary.LittleEndian.PutUint16(buf[1:3], uint16(len(payload)))
	copy(buf[frameHeaderLen:], payload)
	return buf, nil
}

// FrameReader extracts companion frames from a byte stream, resyncing on stray
// bytes exactly like the firmware and meshcore.js read loops: a byte that is not
// a frame marker, and a zero-length frame, are discarded one byte at a time.
type FrameReader struct {
	r *bufio.Reader
}

// NewFrameReader wraps r. It buffers internally, so pass the raw stream.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: bufio.NewReader(r)}
}

// ReadFrame returns the next frame's marker and payload. It skips leading bytes
// until it finds a marker followed by a non-zero length. It returns io.EOF when
// the stream ends cleanly between frames, or io.ErrUnexpectedEOF if the stream
// ends mid-frame. The returned payload is freshly allocated and owned by the
// caller.
func (fr *FrameReader) ReadFrame() (marker byte, payload []byte, err error) {
	for {
		// Resync to a marker byte, discarding anything else.
		b, err := fr.r.ReadByte()
		if err != nil {
			return 0, nil, err
		}
		if b != FrameAppToNode && b != FrameNodeToApp {
			continue
		}

		// Peek the length without consuming, so a truncated marker+length at the
		// tail of a partial frame can resync rather than desync the stream: if
		// these two bytes turn out to be a stray marker's data we still advance
		// one byte at a time on the next iteration.
		hdr, err := fr.r.Peek(2)
		if err != nil {
			if err == io.EOF {
				return 0, nil, io.ErrUnexpectedEOF
			}
			return 0, nil, err
		}
		length := int(binary.LittleEndian.Uint16(hdr))
		if length == 0 {
			// Zero-length frame: discard just the marker and resync.
			continue
		}

		// Commit the length bytes and read the payload.
		if _, err := fr.r.Discard(2); err != nil {
			return 0, nil, err
		}
		buf := make([]byte, length)
		if _, err := io.ReadFull(fr.r, buf); err != nil {
			if err == io.EOF {
				return 0, nil, io.ErrUnexpectedEOF
			}
			return 0, nil, err
		}
		return b, buf, nil
	}
}
