// Package sqlite stores a companion node's contacts, channels and settings in a
// single SQLite database. Changes are committed as they happen, so they survive
// a crash or kill. A power loss can drop the latest commits but leaves the
// database consistent.
package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"

	_ "modernc.org/sqlite" // database/sql driver

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/device/companion"
	"github.com/kabili207/meshcore-go/device/contact"
)

// migrations are applied in order. PRAGMA user_version records how many have
// run, so only ever append to this list.
var migrations = []string{`
	CREATE TABLE contacts (
		id           BLOB PRIMARY KEY CHECK (length(id) = 32),
		name         TEXT NOT NULL,
		type         INTEGER NOT NULL,
		flags        INTEGER NOT NULL,
		out_path_len INTEGER NOT NULL,
		out_path     BLOB,
		last_advert  INTEGER NOT NULL,
		last_mod     INTEGER NOT NULL,
		gps_lat      INTEGER NOT NULL,
		gps_lon      INTEGER NOT NULL,
		sync_since   INTEGER NOT NULL
	);
	CREATE TABLE channels (
		idx    INTEGER PRIMARY KEY,
		name   TEXT NOT NULL,
		secret BLOB
	);
	CREATE TABLE settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);
`}

// Store is a SQLite-backed contact.ContactPersistence and
// companion.Persistence.
type Store struct {
	db     *sql.DB
	closed atomic.Bool
}

var (
	_ contact.ContactPersistence = (*Store)(nil)
	_ companion.Persistence      = (*Store)(nil)
)

// Open opens the database at path, creating it if needed and bringing its schema
// up to date. A new file is readable only by its owner because it holds channel
// keys; SQLite gives its WAL files the same mode.
func Open(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serializes writers, so they never see SQLITE_BUSY.
	db.SetMaxOpenConns(1)

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("schema version %d is newer than supported version %d", version, len(migrations))
	}
	for i := version; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err := tx.Exec(migrations[i]); err != nil {
			return err
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database. Later saves are ignored, since node goroutines can
// outlive it during shutdown.
func (s *Store) Close() error {
	s.closed.Store(true)
	return s.db.Close()
}

// Load returns the saved contacts, oldest first, so that the newest are kept if
// the contact table is now smaller than what was saved.
func (s *Store) Load() ([]*contact.ContactInfo, error) {
	rows, err := s.db.Query(`
		SELECT id, name, type, flags, out_path_len, out_path, last_advert, last_mod,
		       gps_lat, gps_lon, sync_since
		FROM contacts ORDER BY last_mod`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*contact.ContactInfo
	for rows.Next() {
		var id []byte
		c := &contact.ContactInfo{}
		if err := rows.Scan(&id, &c.Name, &c.Type, &c.Flags, &c.OutPathLen, &c.OutPath,
			&c.LastAdvertTimestamp, &c.LastMod, &c.GPSLat, &c.GPSLon, &c.SyncSince); err != nil {
			return nil, err
		}
		copy(c.ID[:], id)
		out = append(out, c)
	}
	return out, rows.Err()
}

// Save inserts or updates a contact. Transient contacts are skipped, as firmware
// does not save them either.
func (s *Store) Save(c *contact.ContactInfo) error {
	if c.IsTransient() || s.closed.Load() {
		return nil
	}
	_, err := s.db.Exec(`
		INSERT INTO contacts (id, name, type, flags, out_path_len, out_path, last_advert,
		                      last_mod, gps_lat, gps_lon, sync_since)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			name = excluded.name, type = excluded.type, flags = excluded.flags,
			out_path_len = excluded.out_path_len, out_path = excluded.out_path,
			last_advert = excluded.last_advert, last_mod = excluded.last_mod,
			gps_lat = excluded.gps_lat, gps_lon = excluded.gps_lon,
			sync_since = excluded.sync_since`,
		c.ID[:], c.Name, c.Type, c.Flags, c.OutPathLen, c.OutPath, c.LastAdvertTimestamp,
		c.LastMod, c.GPSLat, c.GPSLon, c.SyncSince)
	return err
}

// Delete removes a contact.
func (s *Store) Delete(id core.MeshCoreID) error {
	if s.closed.Load() {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM contacts WHERE id = ?`, id[:])
	return err
}

// LoadSettings overlays the saved settings onto v. Each field is its own row, so
// a field added in a later version keeps the value already in v.
func (s *Store) LoadSettings(v *companion.Settings) error {
	rows, err := s.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return err
	}
	defer rows.Close()

	saved := map[string]json.RawMessage{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return err
		}
		saved[key] = json.RawMessage(value)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	data, err := json.Marshal(saved)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// SaveSettings replaces the saved settings in one transaction.
func (s *Store) SaveSettings(v *companion.Settings) error {
	if s.closed.Load() {
		return nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range fields {
		if _, err := tx.Exec(`
			INSERT INTO settings (key, value) VALUES (?, ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
			key, string(value)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadChannels returns every saved channel slot, including cleared ones.
func (s *Store) LoadChannels() ([]companion.Channel, error) {
	rows, err := s.db.Query(`SELECT idx, name, secret FROM channels ORDER BY idx`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []companion.Channel
	for rows.Next() {
		var ch companion.Channel
		if err := rows.Scan(&ch.Index, &ch.Name, &ch.Secret); err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	return out, rows.Err()
}

// SaveChannel inserts or replaces a channel slot.
func (s *Store) SaveChannel(ch companion.Channel) error {
	if s.closed.Load() {
		return nil
	}
	_, err := s.db.Exec(`
		INSERT INTO channels (idx, name, secret) VALUES (?, ?, ?)
		ON CONFLICT (idx) DO UPDATE SET name = excluded.name, secret = excluded.secret`,
		ch.Index, ch.Name, ch.Secret)
	return err
}
