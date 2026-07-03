package node

import (
	"crypto/rand"
	"encoding/binary"

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
		n.handleLogin(e)
	case *event.RequestReceived:
		n.handleRequest(e)
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
// in the ACL and sends a login response. Non-login anon request types
// (regions/owner/clock) are not handled yet.
func (n *RepeaterNode) handleLogin(evt *event.AnonRequestReceived) {
	// Decrypted login data is timestamp(4) + password(null-terminated). Firmware
	// treats data[4] as a login password when it is 0 (blank) or a printable
	// byte; smaller values are typed anon requests (regions/owner/clock).
	if len(evt.Plaintext) < 5 {
		return
	}
	if b := evt.Plaintext[4]; b != 0 && b < ' ' {
		n.log.Debug("ignoring non-login anon request", "type", b)
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

	// Ensure the client is a contact so later addressed REQ/CLI packets decrypt.
	if n.base.Contacts().GetByPubKey(senderID) == nil {
		n.base.Contacts().AddContact(&contact.ContactInfo{
			ID:         senderID,
			OutPathLen: contact.PathUnknown,
			LastMod:    nowTS,
		})
	}

	// A flood-routed login means any stored direct path may be stale; reset it so
	// the path is rediscovered (firmware sets out_path_len to UNKNOWN here).
	if evt.Reply.HasFloodPath() {
		if ct := n.base.Contacts().GetByPubKey(senderID); ct != nil {
			ct.OutPathLen = contact.PathUnknown
		}
	}

	n.log.Info("repeater client logged in", "peer", senderID.String(), "perms", perm)

	resp := buildRepeaterLoginResponse(nowTS, uint8(perm))
	if err := n.base.SendReply(evt.Reply, senderID, codec.PayloadTypeResponse, resp); err != nil {
		n.log.Warn("failed to send login response", "error", err)
	}
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
