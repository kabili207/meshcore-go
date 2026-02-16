package codec

import (
	"bytes"
	"testing"
)

func TestDecodeRS232Frame(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantPayload []byte
		wantRemain  int
		wantErr     error
	}{
		{
			name:    "too short",
			data:    []byte{0xC0, 0x3E},
			wantErr: ErrFrameTooShort,
		},
		{
			name:    "invalid magic",
			data:    []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: ErrInvalidMagic,
		},
		{
			name:    "incomplete frame",
			data:    []byte{0xC0, 0x3E, 0x05, 0x01, 0x02}, // Says 5 bytes payload but only 2 provided
			wantErr: ErrIncompleteFrame,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame, _, err := DecodeRS232Frame(tt.data)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("DecodeRS232Frame() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("DecodeRS232Frame() unexpected error = %v", err)
				return
			}
			if !bytes.Equal(frame.Payload, tt.wantPayload) {
				t.Errorf("DecodeRS232Frame() payload = %v, want %v", frame.Payload, tt.wantPayload)
			}
		})
	}
}

func TestEncodeDecodeRS232Frame(t *testing.T) {
	testCases := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "empty payload",
			payload: []byte{},
		},
		{
			name:    "single byte",
			payload: []byte{0x42},
		},
		{
			name:    "typical packet",
			payload: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		},
		{
			name:    "max size payload",
			payload: make([]byte, MaxTransUnit),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoded, err := EncodeRS232Frame(tc.payload)
			if err != nil {
				t.Fatalf("EncodeRS232Frame() error = %v", err)
			}

			// Verify frame structure
			if len(encoded) != FrameHeaderSize+len(tc.payload)+FrameChecksumSize {
				t.Errorf("encoded length = %d, want %d",
					len(encoded), FrameHeaderSize+len(tc.payload)+FrameChecksumSize)
			}

			// Decode
			frame, remaining, err := DecodeRS232Frame(encoded)
			if err != nil {
				t.Fatalf("DecodeRS232Frame() error = %v", err)
			}

			// Verify payload matches
			if !bytes.Equal(frame.Payload, tc.payload) {
				t.Errorf("decoded payload = %v, want %v", frame.Payload, tc.payload)
			}

			// Verify no remaining data
			if len(remaining) != 0 {
				t.Errorf("remaining bytes = %d, want 0", len(remaining))
			}
		})
	}
}

func TestEncodeRS232FrameTooLarge(t *testing.T) {
	payload := make([]byte, MaxTransUnit+1)
	_, err := EncodeRS232Frame(payload)
	if err != ErrPayloadTooLarge {
		t.Errorf("EncodeRS232Frame() error = %v, want %v", err, ErrPayloadTooLarge)
	}
}

func TestDecodeRS232FrameWithRemaining(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	encoded, _ := EncodeRS232Frame(payload)

	// Add some trailing data
	extra := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	dataWithExtra := append(encoded, extra...)

	frame, remaining, err := DecodeRS232Frame(dataWithExtra)
	if err != nil {
		t.Fatalf("DecodeRS232Frame() error = %v", err)
	}

	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("decoded payload = %v, want %v", frame.Payload, payload)
	}

	if !bytes.Equal(remaining, extra) {
		t.Errorf("remaining = %v, want %v", remaining, extra)
	}
}
