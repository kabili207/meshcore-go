package node

import (
	"sort"
	"sync"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/event"
)

// defaultMaxNeighbors caps the neighbor table when MaxNeighbors is unset.
const defaultMaxNeighbors = 32

// Neighbor ordering for GET_NEIGHBOURS (firmware order_by values).
const (
	neighborOrderNewest    = 0 // newest heard first
	neighborOrderOldest    = 1 // oldest heard first
	neighborOrderStrongest = 2 // highest SNR first
	neighborOrderWeakest   = 3 // lowest SNR first
)

// neighborInfo is a directly-heard repeater neighbor (firmware NeighbourInfo).
type neighborInfo struct {
	id              core.MeshCoreID
	advertTimestamp uint32
	heardTimestamp  uint32 // our clock, seconds
	snr             int8   // SNR x4
}

// neighborTable tracks directly-heard repeater neighbors, evicting the
// least-recently-heard entry when full.
type neighborTable struct {
	mu   sync.Mutex
	max  int
	list []*neighborInfo
}

func newNeighborTable(max int) *neighborTable {
	if max <= 0 {
		max = defaultMaxNeighbors
	}
	return &neighborTable{max: max}
}

// put records or updates a neighbor.
func (t *neighborTable) put(id core.MeshCoreID, advertTS, heardTS uint32, snr int8) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, n := range t.list {
		if n.id == id {
			n.advertTimestamp = advertTS
			n.heardTimestamp = heardTS
			n.snr = snr
			return
		}
	}

	entry := &neighborInfo{id: id, advertTimestamp: advertTS, heardTimestamp: heardTS, snr: snr}
	if len(t.list) < t.max {
		t.list = append(t.list, entry)
		return
	}

	// Evict the least-recently-heard neighbor.
	oldest := t.list[0]
	for _, n := range t.list[1:] {
		if n.heardTimestamp < oldest.heardTimestamp {
			oldest = n
		}
	}
	*oldest = *entry
}

// snapshot returns a copy of the table sorted per orderBy.
func (t *neighborTable) snapshot(orderBy uint8) []neighborInfo {
	t.mu.Lock()
	out := make([]neighborInfo, len(t.list))
	for i, n := range t.list {
		out[i] = *n
	}
	t.mu.Unlock()

	switch orderBy {
	case neighborOrderNewest:
		sort.Slice(out, func(i, j int) bool { return out[i].heardTimestamp > out[j].heardTimestamp })
	case neighborOrderOldest:
		sort.Slice(out, func(i, j int) bool { return out[i].heardTimestamp < out[j].heardTimestamp })
	case neighborOrderStrongest:
		sort.Slice(out, func(i, j int) bool { return out[i].snr > out[j].snr })
	case neighborOrderWeakest:
		sort.Slice(out, func(i, j int) bool { return out[i].snr < out[j].snr })
	}
	return out
}

func (t *neighborTable) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.list)
}

// remove drops every neighbor whose ID begins with prefix, returning how many
// were removed.
func (t *neighborTable) remove(prefix []byte) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	kept := t.list[:0]
	removed := 0
	for _, n := range t.list {
		if matchesPrefix(n.id[:], prefix) {
			removed++
			continue
		}
		kept = append(kept, n)
	}
	t.list = kept
	return removed
}

// recordNeighbor adds a directly-heard repeater advert to the neighbor table.
// Firmware records only zero-hop, non-share adverts from repeater nodes.
func (n *RepeaterNode) recordNeighbor(evt *event.AdvertReceived) {
	pkt := evt.RawPacket
	if pkt == nil || pkt.HopCount() != 0 {
		return // only directly-heard (zero-hop) adverts
	}
	if isShareAdvert(pkt) {
		return
	}
	if evt.Advert == nil || evt.Advert.AppData == nil || evt.Advert.AppData.NodeType != codec.NodeTypeRepeater {
		return // only repeater neighbors
	}
	now := n.base.Clock().GetCurrentTime()
	n.neighbors.put(evt.From, evt.Advert.Timestamp, now, pkt.SNR)
}

// isShareAdvert reports whether a packet is a "share" (transport codes {0,0},
// meaning send-to-nowhere) rather than a directly-heard advert.
func isShareAdvert(pkt *codec.Packet) bool {
	return pkt.HasTransportCodes() && pkt.TransportCodes[0] == 0 && pkt.TransportCodes[1] == 0
}
