package node

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/acl"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
)

// RepeaterFirmwareVersion is the protocol version reported in login responses.
const RepeaterFirmwareVersion = 0x01

// loginResponseSize is timestamp(4) + resp_type(1) + legacy(1) + admin_flag(1) +
// perms(1) + random(4) + version(1).
const loginResponseSize = 13

// dispatchEvents routes BaseNode events to the repeater's admin handlers.
func (n *RepeaterNode) dispatchEvents(evt any) {
	switch e := evt.(type) {
	case *event.AnonRequestReceived:
		n.handleAnonRequest(e)
	case *event.RequestReceived:
		n.handleRequest(e)
	case *event.TextMessageReceived:
		n.handleCLIMessage(e)
	case *event.AdvertReceived:
		n.recordNeighbor(e)
	case *event.PacketReceived:
		// CONTROL packets (node discovery) arrive via the catch-all event.
		if e.RawPacket != nil && e.RawPacket.PayloadType() == codec.PayloadTypeControl {
			n.handleControl(e.RawPacket)
		}
	}
}

// handleLogin authenticates an ANON_REQ login and, on success, records the client
// in the ACL and sends a login response. Typed anon requests (regions/owner/clock)
// are dispatched separately by handleAnonRequest.
func (n *RepeaterNode) handleLogin(evt *event.AnonRequestReceived) {
	// Decrypted login data is timestamp(4) + password(null-terminated).
	if len(evt.Plaintext) < 5 {
		return
	}

	senderTimestamp := binary.LittleEndian.Uint32(evt.Plaintext[0:4])
	password := nullTerminated(evt.Plaintext[4:])
	senderID := evt.From

	existing := n.acl.GetClient(senderID)
	existingPerms := acl.Reject
	if existing != nil {
		existingPerms = int(existing.Permissions)
	}

	perm := n.auth.Resolve(existingPerms, password)
	if perm == acl.Reject {
		n.log.Debug("repeater login rejected", "peer", senderID.String())
		return
	}

	// Replay: a login must be newer than the last one seen from this client.
	if existing != nil && senderTimestamp <= existing.LastTimestamp {
		n.log.Debug("repeater login replay", "peer", senderID.String())
		return
	}

	nowTS := n.base.Clock().GetCurrentTime()
	if _, err := n.acl.AddClient(&acl.Client{
		ID:            senderID,
		Permissions:   uint8(perm),
		OutPathLen:    acl.PathUnknown,
		LastTimestamp: senderTimestamp,
		LastActivity:  nowTS,
	}); err != nil {
		n.log.Warn("repeater ACL full, login dropped", "peer", senderID.String(), "error", err)
		return
	}

	// The login may have evicted another client, so resync rather than just add.
	n.syncPeers()

	// A flood-routed login means any stored direct path may be stale; reset it so
	// the path is rediscovered (firmware sets out_path_len to UNKNOWN here).
	if evt.Reply.HasFloodPath() {
		if ct := n.base.Contacts().GetByPubKey(senderID); ct != nil {
			ct.OutPathLen = contact.PathUnknown
		}
	}

	n.log.Info("repeater client logged in", "peer", senderID.String(), "perms", perm)

	resp := buildRepeaterLoginResponse(nowTS, uint8(perm))
	rc := n.anonReplyContext(evt, nil, 0, false)
	if err := n.base.SendReply(rc, senderID, codec.PayloadTypeResponse, resp); err != nil {
		n.log.Warn("failed to send login response", "error", err)
	}
}

// syncPeers makes the peer table hold exactly the ACL's clients. Firmware's
// repeater looks peers up in its ACL (searchPeersByHash), so only logged-in
// clients can send it addressed packets, and adverts never crowd them out.
func (n *RepeaterNode) syncPeers() {
	peers := n.base.Contacts()
	var stale []core.MeshCoreID
	peers.ForEach(func(ct *contact.ContactInfo) bool {
		if n.acl.GetClient(ct.ID) == nil {
			stale = append(stale, ct.ID)
		}
		return true
	})
	for _, id := range stale {
		_ = peers.RemoveContact(id)
	}

	nowTS := n.base.Clock().GetCurrentTime()
	n.acl.ForEach(func(c *acl.Client) bool {
		if peers.GetByPubKey(c.ID) == nil {
			if _, err := peers.AddContact(&contact.ContactInfo{
				ID:         c.ID,
				OutPathLen: contact.PathUnknown,
				LastMod:    nowTS,
			}); err != nil {
				n.log.Warn("failed to add ACL client as peer", "peer", c.ID.String(), "error", err)
			}
		}
		return true
	})
}

// buildRepeaterLoginResponse builds the 13-byte login-OK response. The admin flag
// (byte 6) is 1 for admins and 0 otherwise, matching the firmware repeater.
func buildRepeaterLoginResponse(nowTS uint32, perms uint8) []byte {
	resp := make([]byte, loginResponseSize)
	binary.LittleEndian.PutUint32(resp[0:4], nowTS)
	resp[4] = codec.RespServerLoginOK
	resp[5] = 0 // legacy keep-alive interval (unused)
	if perms&codec.PermACLRoleMask == codec.PermACLAdmin {
		resp[6] = 1
	}
	resp[7] = perms
	// Random blob so retransmitted responses have distinct packet hashes.
	_, _ = rand.Read(resp[8:12])
	resp[12] = RepeaterFirmwareVersion
	return resp
}

// nullTerminated returns the bytes of data up to the first NUL as a string.
func nullTerminated(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}
