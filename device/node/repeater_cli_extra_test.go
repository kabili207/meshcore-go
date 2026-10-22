package node

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/cli"
	"github.com/kabili207/meshcore-go/device/router"
	"github.com/kabili207/meshcore-go/transport"
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

func TestRepeaterCLI_ProgrammaticConfig(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	changed := map[string]string{}
	n, err := NewRepeater(RepeaterConfig{
		PrivateKey:       ed25519.PrivateKey(kp.PrivateKey),
		AdminPassword:    "adminpw",
		OnSettingChanged: func(k, v string) { changed[k] = v },
	})
	if err != nil {
		t.Fatal(err)
	}

	// LoadConfig applies without firing OnSettingChanged (restoring persisted state).
	if err := n.LoadConfig("name", "Hub"); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if n.appData.Name != "Hub" {
		t.Errorf("name = %q, want Hub", n.appData.Name)
	}
	if len(changed) != 0 {
		t.Errorf("LoadConfig fired OnSettingChanged: %v", changed)
	}

	// GetConfig reads it back.
	if v, ok := n.GetConfig("name"); !ok || v != "Hub" {
		t.Errorf("GetConfig(name) = (%q, %v), want (Hub, true)", v, ok)
	}

	// SetConfig applies and fires OnSettingChanged.
	if err := n.SetConfig("name", "Relay"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if n.appData.Name != "Relay" || changed["name"] != "Relay" {
		t.Errorf("after SetConfig: name=%q changed=%v", n.appData.Name, changed)
	}

	// Unknown key surfaces cli.ErrUnknownKey.
	if err := n.LoadConfig("bogus", "x"); !errors.Is(err, cli.ErrUnknownKey) {
		t.Errorf("LoadConfig(bogus) = %v, want ErrUnknownKey", err)
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

// Firmware v1.18 defaults repeaters to loop.detect minimal. A persisted value,
// applied through LoadConfig, still wins.
func TestRepeater_LoopDetectDefaultsToMinimal(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	if got, _ := n.GetConfig("loop.detect"); got != "minimal" {
		t.Errorf("default loop.detect = %q, want minimal", got)
	}
	if err := n.LoadConfig("loop.detect", "off"); err != nil {
		t.Fatal(err)
	}
	if got := n.base.Router.GetLoopDetect(); got != router.LoopDetectOff {
		t.Errorf("loop detect after loading off = %d, want off", got)
	}
}

// Firmware's repeater defaults to txdelay 0.5 and direct.txdelay 0.3, both
// settable from 0 to 2.
func TestRepeater_RelayDelayDefaultsAndCLI(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	for key, want := range map[string]string{"txdelay": "0.5", "direct.txdelay": "0.3"} {
		if got, _ := n.GetConfig(key); got != want {
			t.Errorf("default %s = %q, want %q", key, got, want)
		}
	}
	if got := n.ExecuteCLI("set txdelay 1.25"); got != "OK" {
		t.Errorf("set txdelay 1.25 = %q", got)
	}
	if f := n.base.Router.GetTxDelayFactor(); f != 1.25 {
		t.Errorf("router txdelay = %v, want 1.25", f)
	}
	for _, cmd := range []string{"set txdelay 3", "set direct.txdelay -1", "set direct.txdelay nope"} {
		if got := n.ExecuteCLI(cmd); got != "Error: must be 0-2" {
			t.Errorf("%q = %q, want Error: must be 0-2", cmd, got)
		}
	}
}

// multi.acks also governs the copies sent ahead of a forwarded ACK.
func TestRepeater_MultiAcksReachesRouter(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	n.base.Router.SetDirectTxDelayFactor(0) // relay at once, so the test needn't wait
	if got := n.ExecuteCLI("set multi.acks 1"); got != "OK" {
		t.Fatalf("set multi.acks 1 = %q", got)
	}

	self := n.base.ID()
	ack := &codec.Packet{
		Header:  (codec.PayloadTypeAck << codec.PHTypeShift) | codec.RouteTypeDirect,
		PathLen: 2,
		Path:    []byte{self[0], 0x99},
		Payload: codec.BuildAckPayload(0x01020304),
	}
	n.base.Router.HandlePacket(ack, transport.PacketSourceMQTT)

	var types []uint8
	for _, p := range ct.snapshot() {
		types = append(types, p.PayloadType())
	}
	if len(types) != 2 || types[0] != codec.PayloadTypeMultipart || types[1] != codec.PayloadTypeAck {
		t.Errorf("forwarded %v, want the multipart copy then the ACK", types)
	}
}
