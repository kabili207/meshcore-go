package telemetry

import (
	"testing"

	cayennelpp "github.com/TheThingsNetwork/go-cayenne-lib"
	"github.com/kabili207/meshcore-go/core/codec"
)

func TestMask(t *testing.T) {
	cases := []struct {
		name        string
		reqData     []byte
		permissions uint8
		want        uint8
	}{
		{"all", []byte{0x00}, codec.PermACLReadWrite, 0xFF},
		{"base only", []byte{0xFE}, codec.PermACLReadWrite, 0x01},
		{"guest forced to zero", []byte{0x00}, codec.PermACLGuest, 0x00},
		{"empty request defaults to all", nil, codec.PermACLAdmin, 0xFF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Mask(tc.reqData, tc.permissions); got != tc.want {
				t.Errorf("Mask(%v, %#x) = %#x, want %#x", tc.reqData, tc.permissions, got, tc.want)
			}
		})
	}
}

func TestEncode_NilProvider(t *testing.T) {
	if got := Encode(nil, []byte{0x00}, codec.PermACLAdmin); got != nil {
		t.Errorf("Encode(nil) = %v, want nil", got)
	}
}

type providerFunc func(uint8, cayennelpp.Encoder)

func (f providerFunc) QuerySensors(p uint8, e cayennelpp.Encoder) { f(p, e) }

func TestEncode_Provider(t *testing.T) {
	var gotMask uint8
	p := providerFunc(func(mask uint8, enc cayennelpp.Encoder) {
		gotMask = mask
		enc.AddTemperature(ChannelSelf, 20.0)
	})

	got := Encode(p, []byte{0xFB}, codec.PermACLReadWrite) // ~0xFB = 0x04
	if gotMask != PermEnvironment {
		t.Errorf("provider mask = %#x, want %#x", gotMask, PermEnvironment)
	}
	want := cayennelpp.NewEncoder()
	want.AddTemperature(ChannelSelf, 20.0)
	if string(got) != string(want.Bytes()) {
		t.Errorf("Encode body = %v, want %v", got, want.Bytes())
	}
}
