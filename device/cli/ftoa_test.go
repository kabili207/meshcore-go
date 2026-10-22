package cli

import "testing"

// Expected values come from firmware's _ftoa (TxtDataHelpers.cpp, v1.18.0)
// compiled and run on the same inputs.
func TestFtoaMatchesFirmware(t *testing.T) {
	for _, tc := range []struct {
		in   float32
		want string
	}{
		{0, "0.0"},
		{915, "915.0"},
		{869.618, "869.6179809"},
		{869.525, "869.5250244"},
		{62.5, "62.5"},
		{250, "250.0"},
		{125, "125.0"},
		{7.8, "7.8000001"},
		{10.4, "10.3999996"},
		{433.175, "433.1749877"},
		{0.5, "0.5"},
		{-12.75, "-12.75"},
		{20, "20.0"},
		{1, "1.0"},
		{906.875, "906.875"},
		{0.1, "0.0999999"},
	} {
		if got := Ftoa(tc.in); got != tc.want {
			t.Errorf("Ftoa(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
