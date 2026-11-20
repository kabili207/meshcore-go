package room

import (
	"testing"

	"github.com/kabili207/meshcore-go/device/router"
)

func TestDefaultStatsProvider_SaturatesDups(t *testing.T) {
	r := router.New(router.Config{})
	r.Counters().FloodDups.Store(70000)
	r.Counters().DirectDups.Store(65534)

	s := NewDefaultStatsProvider(r).GetStats()
	if s.NFloodDups != 0xFFFF || s.NDirectDups != 65534 {
		t.Errorf("dups = flood %d, direct %d; want 65535, 65534", s.NFloodDups, s.NDirectDups)
	}
}
