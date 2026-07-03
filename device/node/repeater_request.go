package node

import (
	"encoding/binary"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/acl"
	"github.com/kabili207/meshcore-go/device/event"
)

const (
	// maxRepeaterReplySize caps a response payload (firmware reply_data budget).
	maxRepeaterReplySize = 60

	// aclPrefixSize is the pubkey prefix length in an access-list entry.
	aclPrefixSize = 6

	// aclEntrySize is one access-list entry: 6-byte prefix + permissions byte.
	aclEntrySize = aclPrefixSize + 1
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
