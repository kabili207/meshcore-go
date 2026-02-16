package core

import (
	"testing"
)

func TestMeshCoreIDString(t *testing.T) {
	id := MeshCoreID{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}

	expected := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	if got := id.String(); got != expected {
		t.Errorf("String() = %s, want %s", got, expected)
	}
}

func TestMeshCoreIDHash(t *testing.T) {
	id := MeshCoreID{0xAB} // Only first byte matters for hash
	if got := id.Hash(); got != 0xAB {
		t.Errorf("Hash() = %02x, want %02x", got, 0xAB)
	}
}

func TestMeshCoreIDIsZero(t *testing.T) {
	var zeroID MeshCoreID
	if !zeroID.IsZero() {
		t.Error("IsZero() = false for zero ID, want true")
	}

	nonZeroID := MeshCoreID{0x01}
	if nonZeroID.IsZero() {
		t.Error("IsZero() = true for non-zero ID, want false")
	}
}

func TestParseMeshCoreID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    MeshCoreID
		wantErr bool
	}{
		{
			name:  "valid 32-byte hex",
			input: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			want: MeshCoreID{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
			},
			wantErr: false,
		},
		{
			name:    "invalid hex characters",
			input:   "xyz123",
			wantErr: true,
		},
		{
			name:    "too short",
			input:   "0102030405",
			wantErr: true,
		},
		{
			name:    "too long",
			input:   "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
			wantErr: true,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMeshCoreID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMeshCoreID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseMeshCoreID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMeshCoreIDRoundTrip(t *testing.T) {
	original := MeshCoreID{
		0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
	}

	// Convert to string and back
	str := original.String()
	parsed, err := ParseMeshCoreID(str)
	if err != nil {
		t.Fatalf("ParseMeshCoreID() error = %v", err)
	}

	if parsed != original {
		t.Errorf("Round trip failed: got %v, want %v", parsed, original)
	}
}

func TestMeshCoreIDBytes(t *testing.T) {
	id := MeshCoreID{0x01, 0x02, 0x03}
	bytes := id.Bytes()

	if len(bytes) != 32 {
		t.Errorf("Bytes() length = %d, want 32", len(bytes))
	}

	if bytes[0] != 0x01 || bytes[1] != 0x02 || bytes[2] != 0x03 {
		t.Errorf("Bytes() content mismatch")
	}
}
