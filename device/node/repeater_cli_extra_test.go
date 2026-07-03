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
