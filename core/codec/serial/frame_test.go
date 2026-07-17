package serial

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestEncodeFrame(t *testing.T) {
	got, err := EncodeFrame(FrameNodeToApp, []byte{RespCodeOK})
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	want := []byte{0x3e, 0x01, 0x00, RespCodeOK} // marker, len=1 LE, payload
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeFrame = %x, want %x", got, want)
	}
}

func TestEncodeFrameOversize(t *testing.T) {
	if _, err := EncodeFrame(FrameNodeToApp, make([]byte, MaxFrameSize+1)); err == nil {
		t.Fatal("expected error for oversize payload")
	}
	if _, err := EncodeFrame(FrameNodeToApp, make([]byte, MaxFrameSize)); err != nil {
		t.Errorf("MaxFrameSize payload should encode: %v", err)
	}
}

func TestReadFrameRoundTrip(t *testing.T) {
	f1, _ := EncodeFrame(FrameAppToNode, []byte{CmdAppStart, 1, 2, 3})
	f2, _ := EncodeFrame(FrameAppToNode, []byte{CmdGetContacts})
	fr := NewFrameReader(bytes.NewReader(append(f1, f2...)))

	m, p, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("frame 1: %v", err)
	}
	if m != FrameAppToNode || !bytes.Equal(p, []byte{CmdAppStart, 1, 2, 3}) {
		t.Errorf("frame 1 = %#x %x", m, p)
	}

	_, p, err = fr.ReadFrame()
	if err != nil {
		t.Fatalf("frame 2: %v", err)
	}
	if !bytes.Equal(p, []byte{CmdGetContacts}) {
		t.Errorf("frame 2 payload = %x", p)
	}

	if _, _, err := fr.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Errorf("expected clean EOF between frames, got %v", err)
	}
}

func TestReadFrameResyncsPastGarbage(t *testing.T) {
	frame, _ := EncodeFrame(FrameNodeToApp, []byte{RespCodeSelfInfo, 0xAA})
	// Prepend stray non-marker bytes the reader must discard.
	stream := append([]byte{0x00, 0x11, 0x22}, frame...)
	fr := NewFrameReader(bytes.NewReader(stream))

	m, p, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if m != FrameNodeToApp || !bytes.Equal(p, []byte{RespCodeSelfInfo, 0xAA}) {
		t.Errorf("resync gave %#x %x", m, p)
	}
}

func TestReadFrameSkipsZeroLength(t *testing.T) {
	// A marker with a zero length must be discarded, then the real frame read.
	zero := []byte{FrameNodeToApp, 0x00, 0x00}
	frame, _ := EncodeFrame(FrameNodeToApp, []byte{RespCodeOK})
	fr := NewFrameReader(bytes.NewReader(append(zero, frame...)))

	if _, p, err := fr.ReadFrame(); err != nil || !bytes.Equal(p, []byte{RespCodeOK}) {
		t.Errorf("after zero-length skip got %x, %v", p, err)
	}
}

func TestReadFrameTruncated(t *testing.T) {
	// Marker + length claiming 4 bytes, but only 2 present.
	fr := NewFrameReader(bytes.NewReader([]byte{FrameAppToNode, 0x04, 0x00, 0x99, 0x88}))
	if _, _, err := fr.ReadFrame(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected ErrUnexpectedEOF, got %v", err)
	}
}
