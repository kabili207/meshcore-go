package router

import (
	"testing"
	"time"
)

// Expected values come from RadioLib 7.7.1's calculateTimeOnAir, compiled with
// MeshCore's settings and run on the same inputs.
func TestAirtimeMatchesRadioLib(t *testing.T) {
	for _, tc := range []struct {
		sf uint8
		bw float64
		cr uint8
		n  int
		ms int
	}{
		{8, 62.5, 5, 10, 177},
		{8, 62.5, 5, 60, 443},
		{8, 62.5, 5, 184, 1078},
		{7, 62.5, 5, 40, 180},
		{7, 62.5, 5, 255, 815},
		{10, 250, 5, 50, 340},
		{11, 250, 5, 50, 641},
		{12, 125, 8, 50, 3547},
		{11, 62.5, 5, 30, 2072}, // low data rate optimization on
		{5, 125, 5, 20, 19},
		{6, 500, 6, 0, 4},
		{9, 125, 7, 100, 775},
	} {
		p := RadioParams{BandwidthKHz: tc.bw, SpreadingFactor: tc.sf, CodingRate: tc.cr}
		if got := p.Airtime(tc.n); got != time.Duration(tc.ms)*time.Millisecond {
			t.Errorf("SF%d/%g/CR%d, %d bytes: Airtime = %v, want %dms", tc.sf, tc.bw, tc.cr, tc.n, got, tc.ms)
		}
	}
}

func TestAirtimeInvalidParams(t *testing.T) {
	for _, p := range []RadioParams{{}, {BandwidthKHz: 62.5, SpreadingFactor: 4, CodingRate: 5}, {BandwidthKHz: 62.5, SpreadingFactor: 8, CodingRate: 9}} {
		if got := p.Airtime(50); got != 0 {
			t.Errorf("%+v: Airtime = %v, want 0", p, got)
		}
	}
}
