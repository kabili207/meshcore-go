package node

import (
	"encoding/binary"
	"testing"
)

func TestRepeaterStats_MarshalBinary(t *testing.T) {
	s := RepeaterStats{
		NPacketsRecv:       0x11111111,
		NRecvFlood:         0x22222222,
		TotalRxAirTimeSecs: 0x33333333,
		NRecvErrors:        0x44444444,
	}
	b := s.MarshalBinary()
	if len(b) != RepeaterStatsSize {
		t.Fatalf("size = %d, want %d", len(b), RepeaterStatsSize)
	}
	// Spot-check offsets, including the repeater-specific tail fields that differ
	// from the room server's ServerStats.
	if got := binary.LittleEndian.Uint32(b[8:12]); got != 0x11111111 {
		t.Errorf("NPacketsRecv@8 = %08x", got)
	}
	if got := binary.LittleEndian.Uint32(b[32:36]); got != 0x22222222 {
		t.Errorf("NRecvFlood@32 = %08x", got)
	}
	if got := binary.LittleEndian.Uint32(b[48:52]); got != 0x33333333 {
		t.Errorf("TotalRxAirTimeSecs@48 = %08x", got)
	}
	if got := binary.LittleEndian.Uint32(b[52:56]); got != 0x44444444 {
		t.Errorf("NRecvErrors@52 = %08x", got)
	}
}
