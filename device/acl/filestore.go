package acl

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/kabili207/meshcore-go/core"
)

// DefaultFlushDebounce is how long FileStore waits after the last change before
// writing to disk, coalescing bursts of updates into one write.
const DefaultFlushDebounce = 2 * time.Second

// persistedClient is the on-disk JSON form of a Client.
type persistedClient struct {
	ID            string `json:"id"` // hex-encoded 32-byte public key
	Name          string `json:"name,omitempty"`
	Permissions   uint8  `json:"permissions"`
	OutPathLen    uint8  `json:"out_path_len"`
	OutPath       string `json:"out_path,omitempty"` // hex-encoded
	LastTimestamp uint32 `json:"last_timestamp,omitempty"`
	LastActivity  uint32 `json:"last_activity,omitempty"`
}

// FileStore is a Persistence backend that stores admin clients as a JSON file.
// Writes are debounced and atomic (temp file + rename). Call Close on shutdown to
// flush any pending write.
type FileStore struct {
	path     string
	debounce time.Duration

	mu      sync.Mutex
	clients map[core.MeshCoreID]persistedClient
	timer   *time.Timer
	closed  bool
}

var _ Persistence = (*FileStore)(nil)

// NewFileStore creates a JSON-file ACL store at the given path.
func NewFileStore(path string) *FileStore {
	return &FileStore{
		path:     path,
		debounce: DefaultFlushDebounce,
		clients:  make(map[core.MeshCoreID]persistedClient),
	}
}

// Load reads the persisted clients. A missing file yields an empty result.
func (f *FileStore) Load() ([]*Client, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var records []persistedClient
	if len(data) > 0 {
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]*Client, 0, len(records))
	for _, r := range records {
		id, err := decodeID(r.ID)
		if err != nil {
			continue
		}
		f.clients[id] = r
		out = append(out, r.toClient(id))
	}
	return out, nil
}

// Save records or updates a client and schedules a debounced write.
func (f *FileStore) Save(c *Client) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clients[c.ID] = toPersisted(c)
	f.scheduleLocked()
	return nil
}

// Delete removes a client and schedules a debounced write.
func (f *FileStore) Delete(id core.MeshCoreID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.clients[id]; !ok {
		return nil // nothing to do; avoid a needless write
	}
	delete(f.clients, id)
	f.scheduleLocked()
	return nil
}

// Flush writes the current clients to disk immediately.
func (f *FileStore) Flush() error {
	f.mu.Lock()
	if f.timer != nil {
		f.timer.Stop()
		f.timer = nil
	}
	records := make([]persistedClient, 0, len(f.clients))
	for _, r := range f.clients {
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
func (f *FileStore) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return f.Flush()
}

// scheduleLocked arms the debounce timer if one is not already pending. Must be
// called with f.mu held.
func (f *FileStore) scheduleLocked() {
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

func toPersisted(c *Client) persistedClient {
	return persistedClient{
		ID:            hex.EncodeToString(c.ID[:]),
		Name:          c.Name,
		Permissions:   c.Permissions,
		OutPathLen:    c.OutPathLen,
		OutPath:       hex.EncodeToString(c.OutPath),
		LastTimestamp: c.LastTimestamp,
		LastActivity:  c.LastActivity,
	}
}

func (r persistedClient) toClient(id core.MeshCoreID) *Client {
	outPath, _ := hex.DecodeString(r.OutPath)
	return &Client{
		ID:            id,
		Name:          r.Name,
		Permissions:   r.Permissions,
		OutPathLen:    r.OutPathLen,
		OutPath:       outPath,
		LastTimestamp: r.LastTimestamp,
		LastActivity:  r.LastActivity,
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
