package kiss

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestEncodeFrame(t *testing.T) {
	tests := []struct {
		name     string
		typeByte byte
		data     []byte
		want     []byte
	}{
		{
			name:     "empty data",
			typeByte: CmdData,
			data:     nil,
			want:     []byte{FEND, 0x00, FEND},
		},
		{
			name:     "plain bytes",
			typeByte: CmdData,
			data:     []byte{0x01, 0x02, 0x03},
			want:     []byte{FEND, 0x00, 0x01, 0x02, 0x03, FEND},
		},
		{
			name:     "escapes FEND in data",
			typeByte: CmdData,
			data:     []byte{0x01, FEND, 0x02},
			want:     []byte{FEND, 0x00, 0x01, FESC, TFEND, 0x02, FEND},
		},
		{
			name:     "escapes FESC in data",
			typeByte: CmdData,
			data:     []byte{FESC},
			want:     []byte{FEND, 0x00, FESC, TFESC, FEND},
		},
		{
			name:     "escapes the type byte too",
			typeByte: FEND,
			data:     []byte{0x07},
			want:     []byte{FEND, FESC, TFEND, 0x07, FEND},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeFrame(tt.typeByte, tt.data)
			if err != nil {
				t.Fatalf("EncodeFrame: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeFrame = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestEncodeFrameOversize(t *testing.T) {
	// The limit counts the type byte, so MaxFrameSize-1 data bytes is the
	// largest frame that fits.
	if _, err := EncodeFrame(CmdData, make([]byte, MaxFrameSize-1)); err != nil {
		t.Errorf("largest legal frame should encode: %v", err)
	}
	_, err := EncodeFrame(CmdData, make([]byte, MaxFrameSize))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("oversize frame error = %v, want ErrFrameTooLarge", err)
	}
}

func TestEncodeDataFrameRejectsOverMTU(t *testing.T) {
	if _, err := EncodeDataFrame(make([]byte, MaxPacketSize)); err != nil {
		t.Errorf("MTU-sized packet should encode: %v", err)
	}
	_, err := EncodeDataFrame(make([]byte, MaxPacketSize+1))
	if !errors.Is(err, ErrPacketTooLarge) {
		t.Errorf("over-MTU packet error = %v, want ErrPacketTooLarge", err)
	}
}

func TestEncodeHardwareFrame(t *testing.T) {
	got, err := EncodeHardwareFrame(HWCmdGetRandom, []byte{16})
	if err != nil {
		t.Fatalf("EncodeHardwareFrame: %v", err)
	}
	want := []byte{FEND, CmdSetHardware, HWCmdGetRandom, 16, FEND}
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeHardwareFrame = %x, want %x", got, want)
	}
}

func TestEncodeHardwareFrameOversize(t *testing.T) {
	if _, err := EncodeHardwareFrame(HWCmdSignData, make([]byte, MaxHardwarePayloadSize)); err != nil {
		t.Errorf("largest legal payload should encode: %v", err)
	}
	_, err := EncodeHardwareFrame(HWCmdSignData, make([]byte, MaxHardwarePayloadSize+1))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("oversize payload error = %v, want ErrFrameTooLarge", err)
	}
}

func TestReadFrameRoundTrip(t *testing.T) {
	f1, _ := EncodeDataFrame([]byte{0x11, FEND, FESC, 0x22})
	f2, _ := EncodeHardwareFrame(HWCmdPing, nil)
	fr := NewFrameReader(bytes.NewReader(append(f1, f2...)))

	typ, data, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("frame 1: %v", err)
	}
	if typ != CmdData {
		t.Errorf("frame 1 type = %#x, want %#x", typ, CmdData)
	}
	if want := []byte{0x11, FEND, FESC, 0x22}; !bytes.Equal(data, want) {
		t.Errorf("frame 1 data = %x, want %x", data, want)
	}

	typ, data, err = fr.ReadFrame()
	if err != nil {
		t.Fatalf("frame 2: %v", err)
	}
	if typ != CmdSetHardware || !bytes.Equal(data, []byte{HWCmdPing}) {
		t.Errorf("frame 2 = %#x %x", typ, data)
	}

	if _, _, err := fr.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Errorf("end of stream error = %v, want io.EOF", err)
	}
}

func TestReadFrameSkipsLeadingJunkAndEmptyFrames(t *testing.T) {
	// Garbage before the first delimiter, then back-to-back delimiters, which
	// KISS streams produce when frames share a boundary byte.
	stream := []byte{0xAA, 0xBB, FEND, FEND, FEND, CmdData, 0x42, FEND}
	fr := NewFrameReader(bytes.NewReader(stream))

	typ, data, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if typ != CmdData || !bytes.Equal(data, []byte{0x42}) {
		t.Errorf("frame = %#x %x, want %#x 42", typ, data, CmdData)
	}
}

func TestReadFrameStrayEscapeDoesNotCorruptTheNextFrame(t *testing.T) {
	// A dangling FESC just before a delimiter. Firmware clears its escape flag
	// on every FEND, so the frame that follows is read intact. Leaving the flag
	// set instead swallows the type byte and shifts the whole frame by one,
	// which turns one byte of line noise into a silently mangled packet.
	stream := []byte{FEND, FESC, FEND, CmdData, TFEND, 0x41, FEND}
	fr := NewFrameReader(bytes.NewReader(stream))

	typ, data, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if typ != CmdData {
		t.Errorf("type = %#x, want %#x", typ, CmdData)
	}
	if want := []byte{TFEND, 0x41}; !bytes.Equal(data, want) {
		t.Errorf("data = %x, want %x", data, want)
	}
}

func TestReadFrameUndefinedEscapeDropsByte(t *testing.T) {
	// FESC followed by something other than TFEND/TFESC: the firmware drops
	// that byte and stays inside the frame.
	stream := []byte{FEND, CmdData, 0x01, FESC, 0x99, 0x02, FEND}
	fr := NewFrameReader(bytes.NewReader(stream))

	_, data, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if want := []byte{0x01, 0x02}; !bytes.Equal(data, want) {
		t.Errorf("data = %x, want %x", data, want)
	}
}

func TestReadFrameTruncated(t *testing.T) {
	fr := NewFrameReader(bytes.NewReader([]byte{FEND, CmdData, 0x01, 0x02}))
	if _, _, err := fr.ReadFrame(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("truncated frame error = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadFrameOversizeResyncs(t *testing.T) {
	var stream []byte
	stream = append(stream, FEND)
	stream = append(stream, make([]byte, MaxFrameSize+10)...) // never terminated in time
	good, _ := EncodeDataFrame([]byte{0x55})
	stream = append(stream, good...)

	fr := NewFrameReader(bytes.NewReader(stream))
	if _, _, err := fr.ReadFrame(); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversize frame error = %v, want ErrFrameTooLarge", err)
	}

	// The reader must stay usable: the next delimiter starts a fresh frame.
	typ, data, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("frame after oversize: %v", err)
	}
	if typ != CmdData || !bytes.Equal(data, []byte{0x55}) {
		t.Errorf("recovered frame = %#x %x", typ, data)
	}
}

func TestTypeByteRoundTrip(t *testing.T) {
	b := TypeByte(3, CmdSetHardware)
	if b != 0x36 {
		t.Errorf("TypeByte(3, SetHardware) = %#x, want 0x36", b)
	}
	port, cmd := SplitTypeByte(b)
	if port != 3 || cmd != CmdSetHardware {
		t.Errorf("SplitTypeByte = port %d cmd %#x", port, cmd)
	}
}

func TestHWResponseFor(t *testing.T) {
	pairs := map[uint8]uint8{
		HWCmdGetIdentity:     HWRespIdentity,
		HWCmdVerifySignature: HWRespVerify,
		HWCmdGetRadio:        HWRespRadio,
		HWCmdGetSignalReport: HWRespSignalReport,
		HWCmdPing:            HWRespPong,
	}
	for cmd, want := range pairs {
		if got := HWResponseFor(cmd); got != want {
			t.Errorf("HWResponseFor(%#x) = %#x, want %#x", cmd, got, want)
		}
	}
}
