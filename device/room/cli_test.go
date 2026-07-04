package room

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/device/cli"
)

func TestRoomCLI_GetSetName(t *testing.T) {
	h := newTestHarness(t)

	if got := h.server.executeCLI("set name Lobby"); got != "OK" {
		t.Fatalf("set name = %q, want OK", got)
	}
	if got := h.server.executeCLI("get name"); got != "Lobby" {
		t.Errorf("get name = %q, want Lobby", got)
	}
}

func TestRoomCLI_LatValidation(t *testing.T) {
	h := newTestHarness(t)

	if got := h.server.executeCLI("set lat 37.5"); got != "OK" {
		t.Errorf("set lat = %q, want OK", got)
	}
	if got := h.server.executeCLI("get lat"); got != "37.500000" {
		t.Errorf("get lat = %q, want 37.500000", got)
	}
	if got := h.server.executeCLI("set lat nope"); got != "Error: bad latitude" {
		t.Errorf("set bad lat = %q, want 'Error: bad latitude'", got)
	}
}

func TestRoomCLI_AllowReadOnly(t *testing.T) {
	h := newTestHarness(t)

	// Harness config sets AllowReadOnly = true.
	if got := h.server.executeCLI("get allow.read.only"); got != "on" {
		t.Errorf("get allow.read.only = %q, want on", got)
	}
	if got := h.server.executeCLI("set allow.read.only off"); got != "OK" {
		t.Errorf("set allow.read.only off = %q, want OK", got)
	}
	if got := h.server.executeCLI("get allow.read.only"); got != "off" {
		t.Errorf("get allow.read.only = %q, want off", got)
	}
	if got := h.server.executeCLI("set allow.read.only maybe"); got != "Error: expected on/off" {
		t.Errorf("set invalid = %q", got)
	}
}

func TestRoomCLI_ReadOnlyKeys(t *testing.T) {
	h := newTestHarness(t)

	want := hex.EncodeToString(h.server.cfg.PublicKey[:])
	if got := h.server.executeCLI("get public.key"); got != want {
		t.Errorf("get public.key = %q, want %q", got, want)
	}
	if got := h.server.executeCLI("get role"); got != "room_server" {
		t.Errorf("get role = %q, want room_server", got)
	}
	// public.key is read-only.
	if got := h.server.executeCLI("set public.key zzz"); got != "??: public.key" {
		t.Errorf("set read-only key = %q, want '??: public.key'", got)
	}
}

func TestRoomCLI_PathHashModeValidation(t *testing.T) {
	h := newTestHarness(t)
	if got := h.server.executeCLI("set path.hash.mode 5"); got != "Error: expected 0, 1, or 2" {
		t.Errorf("set path.hash.mode 5 = %q", got)
	}
	if got := h.server.executeCLI("set path.hash.mode 1"); got != "OK" {
		t.Errorf("set path.hash.mode 1 = %q, want OK", got)
	}
	if got := h.server.executeCLI("get path.hash.mode"); got != "1" {
		t.Errorf("get path.hash.mode = %q, want 1", got)
	}
}

func TestRoomCLI_Unknown(t *testing.T) {
	h := newTestHarness(t)
	if got := h.server.executeCLI("get nope"); got != "??: nope" {
		t.Errorf("get unknown = %q", got)
	}
	if got := h.server.executeCLI("frobnicate"); got != "Unknown command" {
		t.Errorf("unknown command = %q", got)
	}
}

func TestRoomCLI_Version(t *testing.T) {
	h := newTestHarness(t)

	// With no build date, the reply still carries the firmware version and a
	// "(Build: ...)" portion the phone apps parse.
	want := cli.FirmwareVersion + " (Build: unknown)"
	if got := h.server.executeCLI("ver"); got != want {
		t.Errorf("ver = %q, want %q", got, want)
	}
	// "version" is an alias for "ver".
	if got := h.server.executeCLI("version"); got != want {
		t.Errorf("version = %q, want %q", got, want)
	}

	// A caller-supplied build date is formatted the firmware way.
	h.server.cfg.FirmwareBuildDate = "6 Jun 2026"
	h.server.cli = h.server.buildCLI()
	want = cli.FirmwareVersion + " (Build: 6 Jun 2026)"
	if got := h.server.executeCLI("ver"); got != want {
		t.Errorf("ver = %q, want %q", got, want)
	}

	// An explicit Version override wins verbatim.
	h.server.cfg.Version = "custom-build"
	h.server.cli = h.server.buildCLI()
	if got := h.server.executeCLI("ver"); got != "custom-build" {
		t.Errorf("ver override = %q, want custom-build", got)
	}
}

func TestRoomCLI_AfterSetHook(t *testing.T) {
	h := newTestHarness(t)
	var gotKey, gotVal string
	h.server.cfg.OnSettingChanged = func(k, v string) { gotKey, gotVal = k, v }
	// Rebuild the dispatcher so it picks up the hook (normally set before NewServer).
	h.server.cli = h.server.buildCLI()

	h.server.executeCLI("set name Hall")
	if gotKey != "name" || gotVal != "Hall" {
		t.Errorf("OnSettingChanged(%q,%q), want (name, Hall)", gotKey, gotVal)
	}
}

func TestRoomCLI_ClockReports(t *testing.T) {
	h := newTestHarness(t)
	// "clock" and "clock sync" both report the time; neither returns "OK" (we
	// never let a client override the server clock).
	for _, cmd := range []string{"clock", "clock sync"} {
		got := h.server.executeCLI(cmd)
		if got == "OK" || !strings.Contains(got, "UTC") {
			t.Errorf("%q = %q, want a UTC time string", cmd, got)
		}
	}
}

func TestRoomCLI_TimeRebootUnsupported(t *testing.T) {
	h := newTestHarness(t)
	if got := h.server.executeCLI("time 1000"); got != "unsupported" {
		t.Errorf("time without callback = %q, want unsupported", got)
	}
	if got := h.server.executeCLI("reboot"); got != "unsupported" {
		t.Errorf("reboot without callback = %q, want unsupported", got)
	}
}

func TestRoomCLI_Callbacks(t *testing.T) {
	h := newTestHarness(t)
	var gotEpoch uint32
	rebooted := make(chan struct{}, 1)
	h.server.cfg.OnSetClock = func(e uint32) error { gotEpoch = e; return nil }
	h.server.cfg.OnReboot = func() { rebooted <- struct{}{} }
	h.server.cli = h.server.buildCLI()

	if got := h.server.executeCLI("time 777"); got != "OK" {
		t.Errorf("time = %q, want OK", got)
	}
	if gotEpoch != 777 {
		t.Errorf("OnSetClock epoch = %d, want 777", gotEpoch)
	}
	if got := h.server.executeCLI("reboot"); got != "OK" {
		t.Errorf("reboot = %q, want OK", got)
	}
	select {
	case <-rebooted:
	case <-time.After(time.Second):
		t.Fatal("OnReboot was not called")
	}
}

func TestRoomCLI_Password(t *testing.T) {
	h := newTestHarness(t)
	if got := h.server.executeCLI("password hunter2"); got != "OK" {
		t.Errorf("password = %q, want OK", got)
	}
	if h.server.cfg.AdminPassword != "hunter2" {
		t.Errorf("AdminPassword = %q, want hunter2", h.server.cfg.AdminPassword)
	}
	if got := h.server.executeCLI("password"); !strings.HasPrefix(got, "Error:") {
		t.Errorf("password (no arg) = %q, want an error", got)
	}
}

func TestRoomCLI_GetACL(t *testing.T) {
	h := newTestHarness(t)
	if got := h.server.executeCLI("get acl"); got != "(no clients)" {
		t.Errorf("empty acl = %q, want (no clients)", got)
	}
}

func TestRoomCLI_FloodCaps(t *testing.T) {
	h := newTestHarness(t)
	r := h.server.cfg.Router

	if got := h.server.executeCLI("set flood.max 20"); got != "OK" {
		t.Fatalf("set flood.max = %q, want OK", got)
	}
	if r.GetMaxFloodHops() != 20 {
		t.Errorf("flood.max = %d, want 20", r.GetMaxFloodHops())
	}
	if got := h.server.executeCLI("set flood.max.advert 5"); got != "OK" {
		t.Fatalf("set flood.max.advert = %q, want OK", got)
	}
	if r.GetMaxAdvertFloodHops() != 5 {
		t.Errorf("flood.max.advert = %d, want 5", r.GetMaxAdvertFloodHops())
	}
	if got := h.server.executeCLI("set flood.max.unscoped 30"); got != "OK" {
		t.Fatalf("set flood.max.unscoped = %q, want OK", got)
	}
	if r.GetMaxUnscopedFloodHops() != 30 {
		t.Errorf("flood.max.unscoped = %d, want 30", r.GetMaxUnscopedFloodHops())
	}
	if got := h.server.executeCLI("set flood.max nope"); got != "Error: expected a non-negative number" {
		t.Errorf("bad value = %q", got)
	}
}

func TestRoomCLI_OwnerInfo(t *testing.T) {
	h := newTestHarness(t)
	if got := h.server.executeCLI("set owner.info café owner"); got != "OK" {
		t.Fatalf("set owner.info = %q, want OK", got)
	}
	if h.server.cfg.OwnerInfo != "café owner" {
		t.Errorf("OwnerInfo = %q", h.server.cfg.OwnerInfo)
	}
	if got := h.server.executeCLI("get owner.info"); got != "café owner" {
		t.Errorf("get owner.info = %q", got)
	}
}

func TestRoomCLI_Stats(t *testing.T) {
	h := newTestHarness(t)
	if got := h.server.executeCLI("stats-packets"); !strings.Contains(got, "recv=") {
		t.Errorf("stats-packets = %q, want a recv= line", got)
	}
	if got := h.server.executeCLI("stats-core"); !strings.Contains(got, "clients=") {
		t.Errorf("stats-core = %q, want a clients= line", got)
	}
	if got := h.server.executeCLI("stats-radio"); got != "unsupported" {
		t.Errorf("stats-radio = %q, want unsupported", got)
	}
}
