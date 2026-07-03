package node

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
)

// discoverPendingWindow is how long a self-issued discover request accepts
// matching responses (firmware uses 60s).
const discoverPendingWindow = 60 * time.Second

// handleControl processes a zero-hop node-discovery CONTROL packet. The repeater
// receives these via the PacketReceived catch-all event (CONTROL has no
// dedicated handler in BaseNode).
func (n *RepeaterNode) handleControl(pkt *codec.Packet) {
	if pkt.HopCount() != 0 {
		return // firmware only processes zero-hop control packets
	}
	ctrl, err := codec.ParseControlPayload(pkt.Payload)
	if err != nil {
		return
	}
	if ctrl.Flags&codec.ControlFlagNodeDiscover == 0 {
		return
	}
	switch ctrl.Subtype {
	case codec.ControlSubtypeDiscoverReq:
		n.handleDiscoverReq(pkt, ctrl)
	case codec.ControlSubtypeDiscoverResp:
		n.handleDiscoverResp(pkt, ctrl)
	}
}

// handleDiscoverReq answers a NODE_DISCOVER_REQ that asks for repeaters, subject
// to the discover rate limit, with a zero-hop response carrying our identity and
// the request's inbound SNR.
func (n *RepeaterNode) handleDiscoverReq(pkt *codec.Packet, ctrl *codec.ControlPayload) {
	if !n.discoverLimiter.allow(n.base.Clock().GetCurrentTime()) {
		return
	}
	req, err := codec.ParseDiscoverReqFromControl(ctrl)
	if err != nil {
		return
	}
	if req.TypeFilter&(1<<codec.NodeTypeRepeater) == 0 {
		return // request isn't looking for repeaters
	}

	pub := n.base.PublicKey()
	key := pub[:]
	if req.PrefixOnly {
		key = pub[:8]
	}
	respData := codec.BuildNodeDiscoverRespPayload(codec.NodeTypeRepeater, pkt.SNR, req.Tag, key)
	resp := codec.NewPacket(codec.PayloadTypeControl, codec.RouteTypeDirect, respData)
	n.base.Router.SendZeroHop(resp)
}

// handleDiscoverResp records a repeater that answered our own discover request.
func (n *RepeaterNode) handleDiscoverResp(pkt *codec.Packet, ctrl *codec.ControlPayload) {
	n.discoverMu.Lock()
	tag := n.pendingDiscoverTag
	expired := n.pendingDiscoverUntil.IsZero() || time.Now().After(n.pendingDiscoverUntil)
	n.discoverMu.Unlock()

	if tag == 0 || expired {
		return
	}

	resp, err := codec.ParseDiscoverRespFromControl(ctrl)
	if err != nil {
		return
	}
	if resp.NodeType != codec.NodeTypeRepeater || resp.Tag != tag {
		return
	}
	if len(resp.PubKey) < len(core.MeshCoreID{}) {
		return // need the full key to record a neighbor
	}
	var id core.MeshCoreID
	copy(id[:], resp.PubKey)
	if id == n.base.ID() {
		return
	}
	now := n.base.Clock().GetCurrentTime()
	n.neighbors.put(id, now, now, pkt.SNR)
}

// SendNodeDiscover broadcasts a zero-hop request for nearby repeaters. Matching
// responses are recorded as neighbors for the next discoverPendingWindow.
func (n *RepeaterNode) SendNodeDiscover() {
	var tagBytes [4]byte
	_, _ = rand.Read(tagBytes[:])
	tag := binary.LittleEndian.Uint32(tagBytes[:])

	n.discoverMu.Lock()
	n.pendingDiscoverTag = tag
	n.pendingDiscoverUntil = time.Now().Add(discoverPendingWindow)
	n.discoverMu.Unlock()

	data := codec.BuildNodeDiscoverReqPayload(1<<codec.NodeTypeRepeater, tag, 0)
	pkt := codec.NewPacket(codec.PayloadTypeControl, codec.RouteTypeDirect, data)
	n.base.Router.SendZeroHop(pkt)
}
