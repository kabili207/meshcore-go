package codec

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncodeBridgeFrame_KnownBytes(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		want   []byte
	}{
		{"no secret", "", []byte{0xC0, 0x3E, 0x04, 0x03, 0x01, 0x02}},
		// The XOR covers the checksum and payload but never the magic.
		{"with secret", "ab", []byte{0xC0, 0x3E, 0x65, 0x61, 0x60, 0x60}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeBridgeFrame([]byte{0x01, 0x02}, tt.secret)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("got % x, want % x", got, tt.want)
			}
		})
	}
}

func TestBridgeFrame_RoundTrip(t *testing.T) {
	payload := make([]byte, MaxTransUnit)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	for _, secret := range []string{"", "k", "fifteen-chars!!"} {
		frame, err := EncodeBridgeFrame(payload, secret)
		if err != nil {
			t.Fatalf("secret %q: encode: %v", secret, err)
		}
		got, err := DecodeBridgeFrame(frame, secret)
		if err != nil {
			t.Fatalf("secret %q: decode: %v", secret, err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("secret %q: payload did not round-trip", secret)
		}
	}
}

func TestEncodeBridgeFrame_TooLarge(t *testing.T) {
	_, err := EncodeBridgeFrame(make([]byte, MaxTransUnit+1), "")
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("expected ErrPayloadTooLarge, got %v", err)
	}
}

func TestDecodeBridgeFrame_Errors(t *testing.T) {
	good, _ := EncodeBridgeFrame([]byte{0x01, 0x02, 0x03}, "secret")

	corrupt := bytes.Clone(good)
	corrupt[len(corrupt)-1] ^= 0xFF

	badMagic := bytes.Clone(good)
	badMagic[0] = 0x00

	tests := []struct {
		name   string
		data   []byte
		secret string
		want   error
	}{
		{"too short", []byte{0xC0, 0x3E, 0x00}, "secret", ErrFrameTooShort},
		{"bad magic", badMagic, "secret", ErrInvalidMagic},
		{"raw packet", []byte{0x11, 0x00, 0xAA, 0xBB, 0xCC}, "secret", ErrInvalidMagic},
		{"too large", append([]byte{0xC0, 0x3E}, make([]byte, MaxTransUnit+3)...), "secret", ErrPayloadTooLarge},
		{"corrupt payload", corrupt, "secret", ErrChecksumMismatch},
		{"wrong secret", good, "other", ErrChecksumMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeBridgeFrame(tt.data, tt.secret)
			if !errors.Is(err, tt.want) {
				t.Errorf("expected %v, got %v", tt.want, err)
			}
		})
	}
}
