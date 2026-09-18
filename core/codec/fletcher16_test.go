package codec

import "testing"

func TestFletcher16_KnownValues(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint16
	}{
		{"small", []byte{0x01, 0x02}, 0x0403},
		// Running sum exceeds 255 before the modulo. Computed with the
		// firmware's BridgeBase::fletcher16, where uint8_t promotes to int.
		{"byte overflow", []byte{200, 100}, 0xf52d},
		{"all ones", []byte{0xff, 0xff, 0xff}, 0x0000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Fletcher16(tt.data); got != tt.want {
				t.Errorf("Fletcher16(% x) = %04x, want %04x", tt.data, got, tt.want)
			}
		})
	}
}
