package codec

import (
	"testing"
)

func TestFletcher16(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint16
	}{
		{
			name:     "empty data",
			data:     []byte{},
			expected: 0x0000,
		},
		{
			name:     "single byte zero",
			data:     []byte{0x00},
			expected: 0x0000,
		},
		{
			name:     "single byte 0x01",
			data:     []byte{0x01},
			expected: 0x0101,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Fletcher16(tt.data)
			if result != tt.expected {
				t.Errorf("Fletcher16(%v) = %04x, want %04x", tt.data, result, tt.expected)
			}
		})
	}
}

func TestFletcher16Consistency(t *testing.T) {
	// Test that the same input always produces the same output
	data := []byte("test data for fletcher16")
	checksum1 := Fletcher16(data)
	checksum2 := Fletcher16(data)
	if checksum1 != checksum2 {
		t.Errorf("Fletcher16 not consistent: %04x != %04x", checksum1, checksum2)
	}

	// Different data should produce different checksum (with high probability)
	data2 := []byte("different test data")
	checksum3 := Fletcher16(data2)
	if checksum1 == checksum3 {
		t.Log("Warning: collision detected (unlikely but possible)")
	}
}

func TestValidateChecksum(t *testing.T) {
	data := []byte("test data")
	checksum := Fletcher16(data)

	if !ValidateChecksum(data, checksum) {
		t.Error("ValidateChecksum should return true for correct checksum")
	}

	if ValidateChecksum(data, checksum+1) {
		t.Error("ValidateChecksum should return false for incorrect checksum")
	}
}
