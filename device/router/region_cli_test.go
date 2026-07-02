package router

import (
	"strings"
	"testing"
)

// runCLI splits a "region ..." command line (without the leading "region") and
// dispatches it.
func runCLI(m *RegionMap, line string, save func() error) string {
	return m.HandleCLICommand(strings.Fields(line), save)
}

func TestRegionCLIPutGetRemove(t *testing.T) {
	m := NewRegionMap(nil)

	if got := runCLI(m, "put #us", nil); got != "OK" {
		t.Fatalf("put: %q", got)
	}
	if m.FindByName("us") == nil {
		t.Fatal("put did not create the region")
	}

	// New regions deny flood, so get shows no trailing "F".
	if got := runCLI(m, "get us", nil); got != " #us " {
		t.Errorf("get (denied): %q, want %q", got, " #us ")
	}

	if got := runCLI(m, "allowf us", nil); got != "OK" {
		t.Errorf("allowf: %q", got)
	}
	if got := runCLI(m, "get us", nil); got != " #us F" {
		t.Errorf("get (allowed): %q, want %q", got, " #us F")
	}

	if got := runCLI(m, "denyf us", nil); got != "OK" {
		t.Errorf("denyf: %q", got)
	}
	if m.FindByName("us").Flags&RegionDenyFlood == 0 {
		t.Error("denyf did not set the flag")
	}

	if got := runCLI(m, "remove us", nil); got != "OK" {
		t.Errorf("remove: %q", got)
	}
	if m.Count() != 0 {
		t.Errorf("count after remove = %d, want 0", m.Count())
	}
}

func TestRegionCLIPutWithParent(t *testing.T) {
	m := NewRegionMap(nil)
	runCLI(m, "put #na", nil)
	if got := runCLI(m, "put #us na", nil); got != "OK" {
		t.Fatalf("put with parent: %q", got)
	}

	us := m.FindByName("us")
	na := m.FindByName("na")
	if us == nil || na == nil || us.Parent != na.ID {
		t.Error("child region not parented to #na")
	}

	// get shows the parent in parentheses.
	if got := runCLI(m, "get us", nil); got != " #us (#na) " {
		t.Errorf("get with parent: %q, want %q", got, " #us (#na) ")
	}

	if got := runCLI(m, "put #x #missing", nil); got != "Err - unknown parent" {
		t.Errorf("put with missing parent: %q", got)
	}
}

func TestRegionCLIRemoveErrors(t *testing.T) {
	m := NewRegionMap(nil)
	runCLI(m, "put #parent", nil)
	runCLI(m, "put #child parent", nil)

	if got := runCLI(m, "remove parent", nil); got != "Err - not empty" {
		t.Errorf("remove with children: %q", got)
	}
	if got := runCLI(m, "remove #nope", nil); got != "Err - not found" {
		t.Errorf("remove missing: %q", got)
	}
}

func TestRegionCLIHome(t *testing.T) {
	m := NewRegionMap(nil)
	runCLI(m, "put #us", nil)

	if got := runCLI(m, "home", nil); got != " home is *" {
		t.Errorf("home (default): %q", got)
	}
	if got := runCLI(m, "home us", nil); got != " home is now #us" {
		t.Errorf("home set: %q", got)
	}
	if got := runCLI(m, "home", nil); got != " home is #us" {
		t.Errorf("home (after set): %q", got)
	}
	if got := runCLI(m, "home #missing", nil); got != "Err - unknown region" {
		t.Errorf("home missing: %q", got)
	}
}

func TestRegionCLIList(t *testing.T) {
	m := NewRegionMap(nil)
	runCLI(m, "put #us", nil)
	runCLI(m, "allowf us", nil)
	runCLI(m, "put #eu", nil) // stays denied

	// Wildcard defaults to flood-allowed, so it shows in "allowed".
	if got := runCLI(m, "list allowed", nil); got != "*,us" {
		t.Errorf("list allowed: %q, want %q", got, "*,us")
	}
	if got := runCLI(m, "list denied", nil); got != "eu" {
		t.Errorf("list denied: %q, want %q", got, "eu")
	}
	if got := runCLI(m, "list bogus", nil); got != "Err - use 'allowed' or 'denied'" {
		t.Errorf("list bogus: %q", got)
	}
}

func TestRegionCLISave(t *testing.T) {
	m := NewRegionMap(nil)

	if got := runCLI(m, "save", nil); got != "Err - save not supported" {
		t.Errorf("save without callback: %q", got)
	}

	saved := false
	ok := func() error { saved = true; return nil }
	if got := runCLI(m, "save", ok); got != "OK" || !saved {
		t.Errorf("save with callback: %q saved=%v", got, saved)
	}

	failErr := func() error { return errTest }
	if got := runCLI(m, "save", failErr); got != "Err - save failed" {
		t.Errorf("save failure: %q", got)
	}
}

func TestRegionCLIUnknownAndExport(t *testing.T) {
	m := NewRegionMap(nil)
	na := m.PutRegion("#na", 0, 0)
	allowFlood(na)

	// Bare "region" dumps the hierarchy, wildcard first. With no home set it
	// defaults to the wildcard (id 0), which is marked "^".
	if got := runCLI(m, "", nil); !strings.HasPrefix(got, "*^ F") {
		t.Errorf("bare region export: %q", got)
	}
	if got := runCLI(m, "frobnicate", nil); got != "Err - ??" {
		t.Errorf("unknown subcommand: %q", got)
	}
	if got := runCLI(m, "allowf", nil); got != "Err - unknown region" {
		t.Errorf("allowf without name: %q", got)
	}
}

var errTest = errTestType("boom")

type errTestType string

func (e errTestType) Error() string { return string(e) }
