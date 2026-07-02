package router

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kabili207/meshcore-go/core/codec"
)

// RegionMap is the region policy layer for a repeater. It holds a hierarchy of
// named regions, each with an id, a parent, and forwarding flags, plus a special
// wildcard "*" root region. A repeater consults FindMatch (for scoped
// TRANSPORT_FLOOD packets) and the wildcard flags (for unscoped FLOOD packets)
// to decide whether to forward a flood.
//
// This corresponds to the firmware's RegionMap (src/helpers/RegionMap.cpp).
//
// Region names come in three forms, distinguished by their first character:
//   - "$name" — private region; keys are supplied out of band via the
//     TransportKeyStore rather than derived from the name.
//   - "#name" — auto hashtag region; the key is TransportKeyFromRegion("#name").
//   - "name"  — implicit hashtag region; treated as "#name" (the key derivation
//     normalizes the leading '#'), so "us" and "#us" are the same region.
type RegionMap struct {
	store    *TransportKeyStore
	nextID   uint16
	homeID   uint16
	regions  []RegionEntry
	wildcard RegionEntry
}

const (
	// MaxRegionEntries bounds the number of non-wildcard regions, matching the
	// firmware's MAX_REGION_ENTRIES.
	MaxRegionEntries = 32

	// regionNameField is the fixed on-disk size of a region name (max 30 chars
	// plus a NUL terminator), matching the firmware's char name[31].
	regionNameField = 31

	// RegionDenyFlood, when set in a region's flags, means the region does not
	// forward flood packets.
	RegionDenyFlood = 0x01
	// RegionDenyDirect is reserved for future use (direct forwarding is not yet
	// region-gated in the firmware).
	RegionDenyDirect = 0x02

	// On-disk layout sizes for the firmware "/regions2" format.
	regionHeaderSize = 10  // 5 reserved + home_id(2) + wildcard flags(1) + next_id(2)
	regionEntrySize  = 164 // id(2) + parent(2) + name(31) + flags(1) + 128 reserved
)

// RegionEntry is a single region in the map.
type RegionEntry struct {
	ID     uint16
	Parent uint16
	Flags  uint8
	Name   string
}

// NewRegionMap creates an empty map with only the wildcard "*" region. If store
// is nil, an empty in-memory key store is created for "$" private regions.
func NewRegionMap(store *TransportKeyStore) *RegionMap {
	if store == nil {
		store = NewTransportKeyStore()
	}
	return &RegionMap{
		store:    store,
		nextID:   1,
		regions:  make([]RegionEntry, 0, MaxRegionEntries),
		wildcard: RegionEntry{Name: "*"},
	}
}

// IsNameChar reports whether c is allowed in a region name. It accepts
// alphanumerics and accented bytes plus '-', '$' and '#', excluding most
// punctuation. Matches the firmware's RegionMap::is_name_char.
func IsNameChar(c byte) bool {
	return c == '-' || c == '$' || c == '#' || (c >= '0' && c <= '9') || c >= 'A'
}

// skipHash returns name without a single leading '#', so names are matched
// independently of the hashtag prefix.
func skipHash(name string) string {
	if len(name) > 0 && name[0] == '#' {
		return name[1:]
	}
	return name
}

// PutRegion adds a new region or re-parents an existing one. When id is 0 a new
// id is auto-assigned from the running counter; a non-zero id is used verbatim
// (used when reconstructing a map). New regions default to RegionDenyFlood
// (deny) until explicitly allowed. Returns nil on an invalid name, when full,
// or when the parent would be the region itself.
//
// The returned pointer is valid until the next mutating call on the map.
func (m *RegionMap) PutRegion(name string, parentID uint16, id uint16) *RegionEntry {
	for i := 0; i < len(name); i++ {
		if !IsNameChar(name[i]) {
			return nil // illegal name char
		}
	}

	if region := m.FindByName(name); region != nil {
		if region.ID == parentID {
			return nil // invalid parent (cannot be its own parent)
		}
		region.Parent = parentID // re-parent / move in the hierarchy
		return region
	}

	if id == 0 && len(m.regions) >= MaxRegionEntries {
		return nil // full
	}

	entry := RegionEntry{
		Flags:  RegionDenyFlood, // deny by default
		Parent: parentID,
		Name:   truncateName(name),
	}
	if id == 0 {
		entry.ID = m.nextID
		m.nextID++
	} else {
		entry.ID = id
	}
	m.regions = append(m.regions, entry)
	return &m.regions[len(m.regions)-1]
}

// FindMatch returns the first region that (a) permits the operation described
// by mask (its flags do not intersect mask) and (b) produces a transport key
// whose code matches the packet's transport_codes[0]. Returns nil if none match.
//
// Pass RegionDenyFlood as the mask when deciding whether to forward a scoped
// flood. Matches the firmware's RegionMap::findMatch.
func (m *RegionMap) FindMatch(pkt *codec.Packet, mask uint8) *RegionEntry {
	for i := range m.regions {
		region := &m.regions[i]
		if region.Flags&mask != 0 {
			continue // region does not permit this operation
		}

		var keys []TransportKey
		if len(region.Name) > 0 && region.Name[0] == '$' {
			keys = m.store.LoadKeysFor(region.ID) // private region
		} else {
			// "#name" and implicit "name" both derive the auto hashtag key;
			// TransportKeyFromRegion normalizes the leading '#'.
			keys = []TransportKey{TransportKeyFromRegion(region.Name)}
		}

		for j := range keys {
			if keys[j].CalcTransportCode(pkt) == pkt.TransportCodes[0] {
				return region
			}
		}
	}
	return nil
}

// FindByName returns the region with the given name (ignoring a leading '#'),
// or the wildcard for "*", or nil. The returned pointer is valid until the next
// mutating call.
func (m *RegionMap) FindByName(name string) *RegionEntry {
	if name == "*" {
		return &m.wildcard
	}
	name = skipHash(name)
	for i := range m.regions {
		if skipHash(m.regions[i].Name) == name {
			return &m.regions[i]
		}
	}
	return nil
}

// FindByNamePrefix returns the region matching prefix exactly if one exists,
// otherwise the first region whose name starts with prefix, or nil. Leading '#'
// is ignored on both sides. Matches the firmware's findByNamePrefix.
func (m *RegionMap) FindByNamePrefix(prefix string) *RegionEntry {
	if prefix == "*" {
		return &m.wildcard
	}
	prefix = skipHash(prefix)
	var partial *RegionEntry
	for i := range m.regions {
		name := skipHash(m.regions[i].Name)
		if name == prefix {
			return &m.regions[i] // exact match wins
		}
		if strings.HasPrefix(name, prefix) {
			partial = &m.regions[i]
		}
	}
	return partial
}

// FindByID returns the region with the given id, the wildcard for id 0, or nil.
func (m *RegionMap) FindByID(id uint16) *RegionEntry {
	if id == 0 {
		return &m.wildcard
	}
	for i := range m.regions {
		if m.regions[i].ID == id {
			return &m.regions[i]
		}
	}
	return nil
}

// HomeRegion returns the configured home region, or the wildcard when the home
// is unset (home id 0). Never nil unless the home id points at a removed region.
func (m *RegionMap) HomeRegion() *RegionEntry {
	return m.FindByID(m.homeID)
}

// SetHomeRegion sets the home region (nil clears it back to the wildcard).
func (m *RegionMap) SetHomeRegion(home *RegionEntry) {
	if home == nil {
		m.homeID = 0
		return
	}
	m.homeID = home.ID
}

// RemoveRegion removes a region. It fails for the wildcard, for a region that
// still has child regions, or for a region not in the map.
func (m *RegionMap) RemoveRegion(region *RegionEntry) bool {
	if region.ID == 0 {
		return false // cannot remove the wildcard
	}
	for i := range m.regions {
		if m.regions[i].Parent == region.ID {
			return false // must remove child regions first
		}
	}
	for i := range m.regions {
		if m.regions[i].ID == region.ID {
			m.regions = append(m.regions[:i], m.regions[i+1:]...)
			return true
		}
	}
	return false
}

// Clear removes all non-wildcard regions.
func (m *RegionMap) Clear() {
	m.regions = m.regions[:0]
}

// Count returns the number of non-wildcard regions.
func (m *RegionMap) Count() int { return len(m.regions) }

// ByIndex returns the i-th non-wildcard region. The pointer is valid until the
// next mutating call.
func (m *RegionMap) ByIndex(i int) *RegionEntry { return &m.regions[i] }

// Wildcard returns the root "*" region.
func (m *RegionMap) Wildcard() *RegionEntry { return &m.wildcard }

// Store returns the transport key store backing "$" private regions.
func (m *RegionMap) Store() *TransportKeyStore { return m.store }

// ExportNames returns a comma-separated list of region names (without the '#'
// prefix) whose flags match the mask filter. With invert false it lists regions
// that permit the masked operation (flags & mask == 0); with invert true it
// lists those that deny it. The wildcard is included as "*" when it matches.
// Matches the firmware's exportNamesTo.
func (m *RegionMap) ExportNames(mask uint8, invert bool) string {
	matches := func(flags uint8) bool {
		if invert {
			return flags&mask != 0
		}
		return flags&mask == 0
	}

	var names []string
	if matches(m.wildcard.Flags) {
		names = append(names, "*")
	}
	for i := range m.regions {
		if matches(m.regions[i].Flags) {
			names = append(names, skipHash(m.regions[i].Name))
		}
	}
	return strings.Join(names, ",")
}

// Export writes the region hierarchy as indented text, one region per line,
// with an " F" suffix when the region permits flood and a "^" marker on the
// home region. Matches the firmware's exportTo.
func (m *RegionMap) Export(w io.Writer) {
	m.printChildren(w, &m.wildcard, 0)
}

// ExportString returns the same hierarchy dump as Export as a string.
func (m *RegionMap) ExportString() string {
	var sb strings.Builder
	m.Export(&sb)
	return sb.String()
}

func (m *RegionMap) printChildren(w io.Writer, parent *RegionEntry, indent int) {
	home := ""
	if parent.ID == m.homeID {
		home = "^"
	}
	flood := ""
	if parent.Flags&RegionDenyFlood == 0 {
		flood = " F"
	}
	fmt.Fprintf(w, "%s%s%s%s\n", strings.Repeat(" ", indent), skipHash(parent.Name), home, flood)

	for i := range m.regions {
		if m.regions[i].Parent == parent.ID {
			m.printChildren(w, &m.regions[i], indent+1)
		}
	}
}

// MarshalBinary encodes the map in the firmware's "/regions2" file format: a
// 10-byte header (5 reserved bytes, home id, wildcard flags, next id) followed
// by one 164-byte record per region. All integers are little-endian.
func (m *RegionMap) MarshalBinary() []byte {
	buf := make([]byte, regionHeaderSize+len(m.regions)*regionEntrySize)

	// header: buf[0:5] reserved (zero)
	binary.LittleEndian.PutUint16(buf[5:7], m.homeID)
	buf[7] = m.wildcard.Flags
	binary.LittleEndian.PutUint16(buf[8:10], m.nextID)

	off := regionHeaderSize
	for i := range m.regions {
		r := &m.regions[i]
		binary.LittleEndian.PutUint16(buf[off:off+2], r.ID)
		binary.LittleEndian.PutUint16(buf[off+2:off+4], r.Parent)
		copy(buf[off+4:off+4+regionNameField-1], r.Name) // leave NUL terminator + zeros
		buf[off+4+regionNameField-1] = 0
		buf[off+4+regionNameField] = r.Flags
		// buf[off+36:off+164] reserved (zero)
		off += regionEntrySize
	}
	return buf
}

// UnmarshalBinary decodes the firmware "/regions2" format written by
// MarshalBinary, replacing the map's contents.
func (m *RegionMap) UnmarshalBinary(data []byte) error {
	if len(data) < regionHeaderSize {
		return errors.New("region map data too short")
	}

	m.regions = make([]RegionEntry, 0, MaxRegionEntries)
	m.wildcard = RegionEntry{Name: "*"}
	m.homeID = binary.LittleEndian.Uint16(data[5:7])
	m.wildcard.Flags = data[7]
	m.nextID = binary.LittleEndian.Uint16(data[8:10])
	if m.nextID == 0 {
		m.nextID = 1
	}

	off := regionHeaderSize
	for off+regionEntrySize <= len(data) && len(m.regions) < MaxRegionEntries {
		r := RegionEntry{
			ID:     binary.LittleEndian.Uint16(data[off : off+2]),
			Parent: binary.LittleEndian.Uint16(data[off+2 : off+4]),
			Name:   trimName(data[off+4 : off+4+regionNameField]),
			Flags:  data[off+4+regionNameField],
		}
		off += regionEntrySize
		if r.ID >= m.nextID {
			m.nextID = r.ID + 1 // keep next_id valid
		}
		m.regions = append(m.regions, r)
	}
	return nil
}

// truncateName caps a name to the on-disk field capacity (30 chars + NUL).
func truncateName(name string) string {
	if len(name) > regionNameField-1 {
		return name[:regionNameField-1]
	}
	return name
}

// trimName reads a fixed-width, NUL-padded name field into a Go string.
func trimName(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
