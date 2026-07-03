package contact

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/kabili207/meshcore-go/core"
)

// DefaultFlushDebounce is how long FileContactStore waits after the last change
// before writing to disk, coalescing bursts of updates into one write.
const DefaultFlushDebounce = 2 * time.Second

// persistedContact is the on-disk JSON form of a ContactInfo. Transient state
// (the cached shared secret) is intentionally omitted; it is recomputed from the
// public key on load.
type persistedContact struct {
	ID         string `json:"id"` // hex-encoded 32-byte public key
	Name       string `json:"name,omitempty"`
	Type       uint8  `json:"type,omitempty"`
	Flags      uint8  `json:"flags,omitempty"`
	OutPathLen uint8  `json:"out_path_len"`
	OutPath    string `json:"out_path,omitempty"` // hex-encoded
	LastAdvert uint32 `json:"last_advert,omitempty"`
	LastMod    uint32 `json:"last_mod,omitempty"`
	GPSLat     int32  `json:"lat,omitempty"`
	GPSLon     int32  `json:"lon,omitempty"`
	SyncSince  uint32 `json:"sync_since,omitempty"`
}

// FileContactStore is a ContactPersistence backend that stores contacts as a
// JSON file. Writes are debounced and performed atomically (temp file + rename).
// Call Close on shutdown to flush any pending write.
type FileContactStore struct {
	path     string
	debounce time.Duration

	mu       sync.Mutex
	contacts map[core.MeshCoreID]persistedContact
	timer    *time.Timer
	closed   bool
}

var _ ContactPersistence = (*FileContactStore)(nil)

// NewFileContactStore creates a JSON-file contact store at the given path.
func NewFileContactStore(path string) *FileContactStore {
	return &FileContactStore{
		path:     path,
		debounce: DefaultFlushDebounce,
		contacts: make(map[core.MeshCoreID]persistedContact),
	}
}

// Load reads the persisted contacts. A missing file yields an empty result.
func (f *FileContactStore) Load() ([]*ContactInfo, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var records []persistedContact
	if len(data) > 0 {
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]*ContactInfo, 0, len(records))
	for _, r := range records {
		id, err := decodeID(r.ID)
		if err != nil {
			continue // skip malformed entry
		}
		f.contacts[id] = r
		out = append(out, r.toContactInfo(id))
	}
	return out, nil
}

// Save records or updates a contact and schedules a debounced write.
func (f *FileContactStore) Save(c *ContactInfo) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.contacts[c.ID] = toPersisted(c)
	f.scheduleLocked()
	return nil
}

// Delete removes a contact and schedules a debounced write.
func (f *FileContactStore) Delete(id core.MeshCoreID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.contacts, id)
	f.scheduleLocked()
	return nil
}

// Flush writes the current contacts to disk immediately.
func (f *FileContactStore) Flush() error {
	f.mu.Lock()
	if f.timer != nil {
		f.timer.Stop()
		f.timer = nil
	}
	records := make([]persistedContact, 0, len(f.contacts))
	for _, r := range f.contacts {
		records = append(records, r)
	}
	f.mu.Unlock()

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// Close flushes pending changes and stops further debounced writes.
func (f *FileContactStore) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return f.Flush()
}

// scheduleLocked arms the debounce timer if one is not already pending. Must be
// called with f.mu held.
func (f *FileContactStore) scheduleLocked() {
	if f.closed || f.timer != nil {
		return
	}
	f.timer = time.AfterFunc(f.debounce, func() {
		f.mu.Lock()
		f.timer = nil
		f.mu.Unlock()
		_ = f.Flush()
	})
}

func toPersisted(c *ContactInfo) persistedContact {
	return persistedContact{
		ID:         hex.EncodeToString(c.ID[:]),
		Name:       c.Name,
		Type:       c.Type,
		Flags:      c.Flags,
		OutPathLen: c.OutPathLen,
		OutPath:    hex.EncodeToString(c.OutPath),
		LastAdvert: c.LastAdvertTimestamp,
		LastMod:    c.LastMod,
		GPSLat:     c.GPSLat,
		GPSLon:     c.GPSLon,
		SyncSince:  c.SyncSince,
	}
}

func (r persistedContact) toContactInfo(id core.MeshCoreID) *ContactInfo {
	outPath, _ := hex.DecodeString(r.OutPath)
	return &ContactInfo{
		ID:                  id,
		Name:                r.Name,
		Type:                r.Type,
		Flags:               r.Flags,
		OutPathLen:          r.OutPathLen,
		OutPath:             outPath,
		LastAdvertTimestamp: r.LastAdvert,
		LastMod:             r.LastMod,
		GPSLat:              r.GPSLat,
		GPSLon:              r.GPSLon,
		SyncSince:           r.SyncSince,
	}
}

func decodeID(s string) (core.MeshCoreID, error) {
	var id core.MeshCoreID
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, err
	}
	copy(id[:], b)
	return id, nil
}
