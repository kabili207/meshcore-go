package room

import (
	"encoding/hex"
	"testing"
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
	if got := h.server.executeCLI("ver"); got != "meshcore-go" {
		t.Errorf("ver = %q, want meshcore-go", got)
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
