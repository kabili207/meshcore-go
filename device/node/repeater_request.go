package node

import (
	"encoding/binary"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/acl"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/device/telemetry"
)

const (
	// maxRepeaterReplySize caps a response payload (firmware reply_data budget).
	maxRepeaterReplySize = 60

	// aclPrefixSize is the pubkey prefix length in an access-list entry.
	aclPrefixSize = 6

	// aclEntrySize is one access-list entry: 6-byte prefix + permissions byte.
	aclEntrySize = aclPrefixSize + 1

	// maxNeighborResultBytes caps the neighbor entries in a GET_NEIGHBOURS reply
	// (firmware results_buffer is 130 bytes).
	maxNeighborResultBytes = 130

	// neighborRequestMinSize is version(1)+count(1)+offset(2)+order(1)+prefix(1).
	neighborRequestMinSize = 6
)

// handleRequest processes an addressed REQ from an authenticated client. Requests
// from peers not in the ACL are ignored (firmware only accepts REQ/CLI from known
// clients).
func (n *RepeaterNode) handleRequest(evt *event.RequestReceived) {
	client := n.acl.GetClient(evt.From)
	if client == nil {
		n.log.Debug("request from non-client", "peer", evt.From.String())
		return
	}
	client.LastActivity = n.base.Clock().GetCurrentTime()

	switch evt.RequestType {
	case codec.ReqTypeGetStats:
		// Any authenticated client may read status (firmware allows guests).
		n.sendStatus(evt.Reply, evt.From, evt.Tag)
	case codec.ReqTypeGetAccessList:
		if !client.IsAdmin() {
			return
		}
		n.sendAccessList(evt.Reply, evt.From, evt.Tag, evt.RequestData)
	case codec.ReqTypeGetNeighbors:
		// Any authenticated client may query neighbors (firmware allows guests).
		n.sendNeighbors(evt.Reply, evt.From, evt.Tag, evt.RequestData)
	case codec.ReqTypeGetTelemetry:
		// Any authenticated client may read telemetry; guests get base only.
		n.sendTelemetry(evt.Reply, evt.From, evt.Tag, evt.RequestData, client)
	default:
		n.log.Debug("unhandled repeater request", "type", evt.RequestType, "peer", evt.From.String())
	}
}

// sendStatus replies to REQ_TYPE_GET_STATUS with a tag-prefixed RepeaterStats.
func (n *RepeaterNode) sendStatus(reply event.ReplyContext, to core.MeshCoreID, tag uint32) {
	stats := n.buildStats()
	resp := make([]byte, 4+RepeaterStatsSize)
	binary.LittleEndian.PutUint32(resp[0:4], tag)
	copy(resp[4:], stats.MarshalBinary())
	if err := n.base.SendReply(reply, to, codec.PayloadTypeResponse, resp); err != nil {
		n.log.Warn("failed to send status", "error", err)
	}
}

// buildStats populates RepeaterStats from router counters and uptime. Radio and
// hardware fields stay zero on a transport-attached node.
func (n *RepeaterNode) buildStats() RepeaterStats {
	c := n.base.Router.Counters().Snapshot()
	return RepeaterStats{
		NPacketsRecv:    c.PacketsRecv,
		NPacketsSent:    c.PacketsSent,
		NSentFlood:      c.SentFlood,
		NSentDirect:     c.SentDirect,
		NRecvFlood:      c.RecvFlood,
		NRecvDirect:     c.RecvDirect,
		NFloodDups:      uint16(c.FloodDups),
		NDirectDups:     uint16(c.DirectDups),
		TotalUpTimeSecs: uint32(time.Since(n.startTime).Seconds()),
	}
}

// sendTelemetry replies to REQ_TYPE_GET_TELEMETRY with a tag-prefixed CayenneLPP
// buffer from the configured provider. Guests are limited to base telemetry.
func (n *RepeaterNode) sendTelemetry(reply event.ReplyContext, to core.MeshCoreID, tag uint32, reqData []byte, client *acl.Client) {
	if n.cfg.Telemetry == nil {
		return
	}
	body := telemetry.Encode(n.cfg.Telemetry, reqData, client.Permissions)
	resp := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(resp[0:4], tag)
	copy(resp[4:], body)
	if err := n.base.SendReply(reply, to, codec.PayloadTypeResponse, resp); err != nil {
		n.log.Warn("failed to send telemetry", "error", err)
	}
}

// sendAccessList replies to REQ_TYPE_GET_ACCESS_LIST (admin only) with a
// tag-prefixed list of [6-byte pubkey prefix][permissions] entries. Deleted or
// guest (permissions == 0) entries are skipped, matching the firmware.
func (n *RepeaterNode) sendAccessList(reply event.ReplyContext, to core.MeshCoreID, tag uint32, reqData []byte) {
	if len(reqData) >= 2 && (reqData[0] != 0 || reqData[1] != 0) {
		return // reserved params must be zero
	}

	resp := make([]byte, 4, maxRepeaterReplySize)
	binary.LittleEndian.PutUint32(resp[0:4], tag)

	n.acl.ForEach(func(c *acl.Client) bool {
		if c.Permissions == 0 {
			return true
		}
		if len(resp)+aclEntrySize > maxRepeaterReplySize {
			return false
		}
		entry := make([]byte, aclEntrySize)
		copy(entry[0:aclPrefixSize], c.ID[:aclPrefixSize])
		entry[aclPrefixSize] = c.Permissions
		resp = append(resp, entry...)
		return true
	})

	if err := n.base.SendReply(reply, to, codec.PayloadTypeResponse, resp); err != nil {
		n.log.Warn("failed to send access list", "error", err)
	}
}

// sendNeighbors replies to REQ_TYPE_GET_NEIGHBOURS with a tag-prefixed, sorted,
// paginated list of directly-heard repeater neighbors. Request data is
// version(1) + count(1) + offset(2) + order_by(1) + prefix_len(1) [+ random(4)].
// Each entry is [pubkey_prefix][heard_seconds_ago(4)][snr(1)].
func (n *RepeaterNode) sendNeighbors(reply event.ReplyContext, to core.MeshCoreID, tag uint32, reqData []byte) {
	if len(reqData) < neighborRequestMinSize || reqData[0] != 0 {
		return // only request version 0 is supported
	}
	count := int(reqData[1])
	offset := int(binary.LittleEndian.Uint16(reqData[2:4]))
	orderBy := reqData[4]
	prefixLen := int(reqData[5])
	if prefixLen > len(to) {
		prefixLen = len(to)
	}

	sorted := n.neighbors.snapshot(orderBy)
	now := n.base.Clock().GetCurrentTime()

	// Header: tag(4) + neighbours_count(2) + results_count(2).
	resp := make([]byte, 8, 8+maxNeighborResultBytes)
	binary.LittleEndian.PutUint32(resp[0:4], tag)
	binary.LittleEndian.PutUint16(resp[4:6], uint16(len(sorted)))

	entrySize := prefixLen + 5 // prefix + heard_seconds_ago(4) + snr(1)
	results := 0
	for i := offset; i < len(sorted) && results < count; i++ {
		if (len(resp)-8)+entrySize > maxNeighborResultBytes {
			break
		}
		nb := sorted[i]
		entry := make([]byte, entrySize)
		copy(entry[0:prefixLen], nb.id[:prefixLen])
		binary.LittleEndian.PutUint32(entry[prefixLen:prefixLen+4], now-nb.heardTimestamp)
		entry[prefixLen+4] = byte(nb.snr)
		resp = append(resp, entry...)
		results++
	}
	binary.LittleEndian.PutUint16(resp[6:8], uint16(results))

	if err := n.base.SendReply(reply, to, codec.PayloadTypeResponse, resp); err != nil {
		n.log.Warn("failed to send neighbours", "error", err)
	}
}
