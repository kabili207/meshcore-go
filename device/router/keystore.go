package router

// maxStoredKeysPerRegion bounds the number of private keys held for a single
// region id, matching the firmware's findMatch which reads up to 4.
const maxStoredKeysPerRegion = 4

// TransportKeyStore holds the private transport keys used by "$" regions, keyed
// by region id. Unlike the auto keys derived from "#" region names, these keys
// are supplied out of band (they cannot be reconstructed from the region name).
//
// This is an in-memory store. The firmware's TransportKeyStore is a stub for a
// future hardware-backed keystore and does not persist keys either; these keys
// are intentionally not part of the RegionMap's MarshalBinary output.
type TransportKeyStore struct {
	keys map[uint16][]TransportKey
}

// NewTransportKeyStore creates an empty key store.
func NewTransportKeyStore() *TransportKeyStore {
	return &TransportKeyStore{keys: make(map[uint16][]TransportKey)}
}

// LoadKeysFor returns the keys stored for a region id (nil if none).
func (s *TransportKeyStore) LoadKeysFor(id uint16) []TransportKey {
	return s.keys[id]
}

// SaveKeysFor replaces the keys for a region id. At most maxStoredKeysPerRegion
// keys are retained. Passing no keys removes the entry.
func (s *TransportKeyStore) SaveKeysFor(id uint16, keys []TransportKey) {
	if len(keys) == 0 {
		delete(s.keys, id)
		return
	}
	if len(keys) > maxStoredKeysPerRegion {
		keys = keys[:maxStoredKeysPerRegion]
	}
	stored := make([]TransportKey, len(keys))
	copy(stored, keys)
	s.keys[id] = stored
}

// RemoveKeys removes all keys for a region id.
func (s *TransportKeyStore) RemoveKeys(id uint16) {
	delete(s.keys, id)
}

// Clear removes all stored keys.
func (s *TransportKeyStore) Clear() {
	s.keys = make(map[uint16][]TransportKey)
}
