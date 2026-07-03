package node

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/crypto"
)

// Without the opt-in callbacks, clock-setting and reboot report unsupported.
func TestRepeaterCLI_TimeRebootUnsupported(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	if got := n.cli.Execute("time 1000"); got != "unsupported" {
		t.Errorf("time without callback = %q, want unsupported", got)
	}
	if got := n.cli.Execute("reboot"); got != "unsupported" {
		t.Errorf("reboot without callback = %q, want unsupported", got)
	}
}

// With callbacks configured, "time <epoch>" and "reboot" invoke them.
func TestRepeaterCLI_Callbacks(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var gotEpoch uint32
	rebooted := make(chan struct{}, 1)
	n, err := NewRepeater(RepeaterConfig{
		PrivateKey:    ed25519.PrivateKey(kp.PrivateKey),
		AdminPassword: "adminpw",
		OnSetClock:    func(e uint32) error { gotEpoch = e; return nil },
		OnReboot:      func() { rebooted <- struct{}{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := n.cli.Execute("time 12345"); got != "OK" {
		t.Errorf("time = %q, want OK", got)
	}
	if gotEpoch != 12345 {
		t.Errorf("OnSetClock epoch = %d, want 12345", gotEpoch)
	}
	if got := n.cli.Execute("reboot"); got != "OK" {
		t.Errorf("reboot = %q, want OK", got)
	}
	select {
	case <-rebooted:
	case <-time.After(time.Second):
		t.Fatal("OnReboot was not called")
	}
}

func TestRepeaterCLI_NeighborRemove(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	var id core.MeshCoreID
	id[0] = 0xAB
	n.neighbors.put(id, 0, 100, 40)

	if got := n.cli.Execute("neighbor.remove ff"); got != "ERR: neighbor not found" {
		t.Errorf("remove miss = %q, want not found", got)
	}
	if got := n.cli.Execute("neighbor.remove ab"); got != "OK" {
		t.Errorf("remove hit = %q, want OK", got)
	}
	if n.neighbors.count() != 0 {
		t.Errorf("neighbor not removed, count = %d", n.neighbors.count())
	}
}

func TestRepeaterCLI_GetACL(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	if got := n.cli.Execute("get acl"); got != "(no clients)" {
		t.Errorf("empty acl = %q, want (no clients)", got)
	}

	client, _ := crypto.GenerateKeyPair()
	loginAdmin(t, n, client)
	if got := n.cli.Execute("get acl"); !strings.Contains(got, "perms=") {
		t.Errorf("get acl = %q, want a perms line", got)
	}
}

func TestRepeaterCLI_DiscoverNeighbors(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	if got := n.cli.Execute("discover.neighbors"); got != "OK" {
		t.Errorf("discover.neighbors = %q, want OK", got)
	}
}

func TestRepeaterCLI_FloodCaps(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	r := n.base.Router

	if got := n.cli.Execute("set flood.max.advert 5"); got != "OK" {
		t.Fatalf("set flood.max.advert = %q, want OK", got)
	}
	if r.GetMaxAdvertFloodHops() != 5 {
		t.Errorf("flood.max.advert = %d, want 5", r.GetMaxAdvertFloodHops())
	}
	if got := n.cli.Execute("get flood.max.advert"); got != "5" {
		t.Errorf("get flood.max.advert = %q, want 5", got)
	}

	if got := n.cli.Execute("set flood.max.unscoped 30"); got != "OK" {
		t.Fatalf("set flood.max.unscoped = %q, want OK", got)
	}
	if r.GetMaxUnscopedFloodHops() != 30 {
		t.Errorf("flood.max.unscoped = %d, want 30", r.GetMaxUnscopedFloodHops())
	}
	if got := n.cli.Execute("set flood.max.advert nope"); got != "Error: expected a non-negative number" {
		t.Errorf("bad value = %q", got)
	}
}

func TestRepeaterCLI_AdvertIntervals(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")

	if got := n.cli.Execute("set advert.interval 3"); got != "OK" {
		t.Fatalf("set advert.interval = %q, want OK", got)
	}
	if got := n.cli.Execute("get advert.interval"); got != "3" {
		t.Errorf("get advert.interval = %q, want 3", got)
	}
	if got := n.advertSched.LocalInterval(); got != 3 {
		t.Errorf("LocalInterval = %d, want 3", got)
	}

	if got := n.cli.Execute("set flood.advert.interval 6"); got != "OK" {
		t.Fatalf("set flood.advert.interval = %q, want OK", got)
	}
	if got := n.advertSched.FloodInterval(); got != 6 {
		t.Errorf("FloodInterval = %d, want 6", got)
	}
	// Setting one interval must not disturb the other.
	if got := n.advertSched.LocalInterval(); got != 3 {
		t.Errorf("LocalInterval after flood set = %d, want 3", got)
	}
}

func TestRepeaterCLI_MultiAcks(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	if got := n.cli.Execute("set multi.acks 2"); got != "OK" {
		t.Fatalf("set multi.acks = %q, want OK", got)
	}
	if got := n.base.GetExtraAckTransmits(); got != 2 {
		t.Errorf("ExtraAckTransmits = %d, want 2", got)
	}
	if got := n.cli.Execute("get multi.acks"); got != "2" {
		t.Errorf("get multi.acks = %q, want 2", got)
	}
}

func TestRepeaterCLI_OwnerInfo(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	if got := n.cli.Execute("set owner.info hello there"); got != "OK" {
		t.Fatalf("set owner.info = %q, want OK", got)
	}
	if n.cfg.OwnerInfo != "hello there" {
		t.Errorf("OwnerInfo = %q, want %q", n.cfg.OwnerInfo, "hello there")
	}
	if got := n.cli.Execute("get owner.info"); got != "hello there" {
		t.Errorf("get owner.info = %q", got)
	}
}

func TestRepeaterCLI_Stats(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	if got := n.cli.Execute("stats-packets"); !strings.Contains(got, "recv=") {
		t.Errorf("stats-packets = %q, want a recv= line", got)
	}
	if got := n.cli.Execute("stats-core"); !strings.Contains(got, "uptime=") {
		t.Errorf("stats-core = %q, want an uptime= line", got)
	}
	if got := n.cli.Execute("stats-radio"); got != "unsupported" {
		t.Errorf("stats-radio = %q, want unsupported", got)
	}
}
