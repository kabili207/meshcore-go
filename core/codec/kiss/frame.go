package kiss

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrFrameTooLarge is returned when a frame's unescaped length exceeds
	// MaxFrameSize. On the read side the offending frame is discarded and the
	// reader resynchronizes, so the caller may keep reading.
	ErrFrameTooLarge = errors.New("kiss: frame exceeds maximum size")
	// ErrPacketTooLarge is returned when a data frame's payload exceeds
	// MaxPacketSize, which the modem cannot transmit.
	ErrPacketTooLarge = errors.New("kiss: packet exceeds maximum transmission unit")
)

// EncodeFrame builds a complete KISS frame: FEND, the type byte and data with
// FEND and FESC bytes escaped, then a closing FEND.
//
// The size limit applies to the unescaped bytes (type byte plus data), matching
// the modem's receive buffer. The returned slice can be up to twice that long
// once escaping is applied.
func EncodeFrame(typeByte byte, data []byte) ([]byte, error) {
	if 1+len(data) > MaxFrameSize {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrFrameTooLarge, 1+len(data), MaxFrameSize)
	}

	// Worst case every byte escapes, plus the two delimiters.
	buf := make([]byte, 0, 2*(1+len(data))+2)
	buf = append(buf, FEND)
	buf = appendEscaped(buf, typeByte)
	for _, b := range data {
		buf = appendEscaped(buf, b)
	}
	return append(buf, FEND), nil
}

// EncodeDataFrame builds a port 0 data frame carrying a raw mesh packet.
func EncodeDataFrame(packet []byte) ([]byte, error) {
	if len(packet) > MaxPacketSize {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrPacketTooLarge, len(packet), MaxPacketSize)
	}
	return EncodeFrame(CmdData, packet)
}

// EncodeHardwareFrame builds a SetHardware frame: the sub-command byte followed
// by its payload.
func EncodeHardwareFrame(subCmd uint8, data []byte) ([]byte, error) {
	if len(data) > MaxHardwarePayloadSize {
		return nil, fmt.Errorf("%w: SetHardware payload %d bytes, limit %d", ErrFrameTooLarge, len(data), MaxHardwarePayloadSize)
	}
	payload := make([]byte, 0, 1+len(data))
	payload = append(payload, byte(subCmd))
	payload = append(payload, data...)
	return EncodeFrame(CmdSetHardware, payload)
}

func appendEscaped(dst []byte, b byte) []byte {
	switch b {
	case FEND:
		return append(dst, FESC, TFEND)
	case FESC:
		return append(dst, FESC, TFESC)
	default:
		return append(dst, b)
	}
}

// FrameReader extracts KISS frames from a byte stream.
//
// It mirrors the firmware's receive loop: bytes before the first FEND are
// discarded, empty frames are skipped, and an unrecognized byte after FESC
// drops that byte rather than the whole frame.
type FrameReader struct {
	r   *bufio.Reader
	buf []byte
}

// NewFrameReader wraps r. It buffers internally, so pass the raw stream.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{
		r:   bufio.NewReader(r),
		buf: make([]byte, 0, MaxFrameSize),
	}
}

// ReadFrame returns the next frame's type byte and its unescaped data, with the
// type byte already stripped from data. The returned slice is freshly allocated
// and owned by the caller.
//
// It returns io.EOF when the stream ends between frames and io.ErrUnexpectedEOF
// when it ends mid-frame. A frame longer than MaxFrameSize yields
// ErrFrameTooLarge; the reader has already resynchronized, so the caller can
// keep reading.
func (fr *FrameReader) ReadFrame() (typeByte byte, data []byte, err error) {
	// Discard anything ahead of the opening delimiter.
	for {
		b, err := fr.r.ReadByte()
		if err != nil {
			return 0, nil, err
		}
		if b == FEND {
			break
		}
	}

	fr.buf = fr.buf[:0]
	escaped := false

	for {
		b, err := fr.r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(fr.buf) > 0 {
				return 0, nil, io.ErrUnexpectedEOF
			}
			return 0, nil, err
		}

		switch {
		case b == FEND:
			if len(fr.buf) == 0 {
				// Back-to-back delimiters. Firmware ignores the empty frame and
				// treats this FEND as the next frame's opener. It also clears
				// the escape flag on every delimiter, so a stray FESC before a
				// boundary cannot eat the next frame's type byte.
				escaped = false
				continue
			}
			out := make([]byte, len(fr.buf)-1)
			copy(out, fr.buf[1:])
			return fr.buf[0], out, nil

		case b == FESC:
			escaped = true
			continue

		case escaped:
			escaped = false
			switch b {
			case TFEND:
				b = FEND
			case TFESC:
				b = FESC
			default:
				// Undefined escape. Firmware drops the byte and stays in frame.
				continue
			}
		}

		if len(fr.buf) >= MaxFrameSize {
			// Overlong frame. Abandon it here rather than consuming to the
			// delimiter: the next call resyncs on the following FEND, which is
			// how the firmware recovers and keeps a shared delimiter usable as
			// the next frame's opener.
			return 0, nil, fmt.Errorf("%w: limit %d", ErrFrameTooLarge, MaxFrameSize)
		}
		fr.buf = append(fr.buf, b)
	}
}
