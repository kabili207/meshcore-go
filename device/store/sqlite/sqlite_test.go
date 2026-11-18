package sqlite

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/companion"
	"github.com/kabili207/meshcore-go/device/contact"
)

func open(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestContactsSurviveReopenWithoutClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "with space.db")
	s := open(t, path)

	var keep, gone, transient core.MeshCoreID
	keep[0], gone[0], transient[0] = 1, 2, 3
	want := &contact.ContactInfo{
		ID: keep, Name: "Alice", Type: codec.NodeTypeChat, Flags: 1, OutPathLen: 0x42,
		OutPath: []byte{1, 2, 3, 4}, LastAdvertTimestamp: 10, LastMod: 20, GPSLat: -30, GPSLon: 40, SyncSince: 50,
	}
	for _, c := range []*contact.ContactInfo{
		want,
		{ID: gone, Type: codec.NodeTypeChat, OutPathLen: contact.PathUnknown},
		{ID: transient, Type: codec.NodeTypeNone, OutPathLen: contact.PathUnknown},
	} {
		if err := s.Save(c); err != nil {
			t.Fatal(err)
		}
	}
	want.Name = "Alice2"
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(gone); err != nil {
		t.Fatal(err)
	}

	// The first store stays open: commits must already be visible.
	got, err := open(t, path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("loaded %d contacts, want 1", len(got))
	}
	c := got[0]
	if c.ID != keep || c.Name != "Alice2" || c.Type != want.Type || c.Flags != 1 || c.OutPathLen != 0x42 ||
		!bytes.Equal(c.OutPath, want.OutPath) || c.LastAdvertTimestamp != 10 || c.LastMod != 20 ||
		c.GPSLat != -30 || c.GPSLon != 40 || c.SyncSince != 50 {
		t.Errorf("loaded contact differs: %+v", c)
	}
}

func TestSettingsOverlayDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	s := open(t, path)

	got := companion.Settings{Name: "default", RadioSF: 11}
	if err := s.LoadSettings(&got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "default" || got.RadioSF != 11 {
		t.Errorf("empty database changed the defaults: %+v", got)
	}

	want := companion.Settings{Name: "saved", AdvLat: -5, TZOffset: -4, RadioFreqKHz: 869525}
	want.DefaultScopeKey[0] = 0xAB
	if err := s.SaveSettings(&want); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM settings WHERE key = 'radio_sf'`); err != nil {
		t.Fatal(err)
	}

	got = companion.Settings{RadioSF: 9}
	if err := s.LoadSettings(&got); err != nil {
		t.Fatal(err)
	}
	want.RadioSF = 9 // no saved value, so the default stays
	if got != want {
		t.Errorf("settings = %+v, want %+v", got, want)
	}
}

func TestChannelsRoundTrip(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "c.db"))
	secret := bytes.Repeat([]byte{7}, 16)
	for _, ch := range []companion.Channel{
		{Index: 0, Name: "", Secret: make([]byte, 16)},
		{Index: 2, Name: "old", Secret: secret},
		{Index: 2, Name: "new", Secret: secret},
	} {
		if err := s.SaveChannel(ch); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.LoadChannels()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Index != 0 || got[0].Name != "" || got[1].Name != "new" || !bytes.Equal(got[1].Secret, secret) {
		t.Errorf("channels = %+v", got)
	}
}

func TestFilesAreOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	s := open(t, filepath.Join(dir, "c.db"))
	if err := s.SaveChannel(companion.Channel{Index: 1, Name: "x", Secret: make([]byte, 16)}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"c.db", "c.db-wal", "c.db-shm"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, perm)
		}
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	open(t, path).Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA user_version = 999`); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(path); err == nil {
		s.Close()
		t.Fatal("expected an error for a newer schema")
	}
}

func TestSavesAfterCloseAreIgnored(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "c.db"))
	s.Close()
	if err := s.Save(&contact.ContactInfo{Type: codec.NodeTypeChat}); err != nil {
		t.Errorf("Save after Close: %v", err)
	}
}
