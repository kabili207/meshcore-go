package node

import (
	"encoding/binary"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/device/router"
)

// handleAnonRequest dispatches a decrypted ANON_REQ. Firmware treats
// plaintext[4] as a login password when it is 0 (blank) or a printable byte;
// smaller values are typed info requests (regions/owner/clock) that are answered
// only when the request arrived direct-routed and within the anon rate limit.
func (n *RepeaterNode) handleAnonRequest(evt *event.AnonRequestReceived) {
	if len(evt.Plaintext) < 5 {
		return
	}
	typeByte := evt.Plaintext[4]
	if typeByte == 0 || typeByte >= ' ' {
		n.handleLogin(evt)
		return
	}
	if evt.RawPacket == nil || !evt.RawPacket.IsDirect() {
		n.log.Debug("ignoring non-direct anon request", "type", typeByte)
		return
	}

	switch typeByte {
	case codec.AnonReqTypeRegions:
		n.respondAnonInfo(evt, n.anonRegionsPayload)
	case codec.AnonReqTypeOwner:
		n.respondAnonInfo(evt, n.anonOwnerPayload)
	case codec.AnonReqTypeBasic:
		n.respondAnonInfo(evt, n.anonClockPayload)
	default:
		n.log.Debug("unknown anon request type", "type", typeByte)
	}
}

// respondAnonInfo builds and sends a RESPONSE for a typed anon request. The
// reply is timestamp(4, echoed as a tag) + now(4, our clock) + the type-specific
// body. It replies direct using the {path-len}{path} the client supplied.
func (n *RepeaterNode) respondAnonInfo(evt *event.AnonRequestReceived, build func() []byte) {
	nowTS := n.base.Clock().GetCurrentTime()
	if !n.anonLimiter.allow(nowTS) {
		return
	}
	path, ok := parseAnonReplyPath(evt.Plaintext[5:])
	if !ok {
		return
	}

	body := build()
	reply := make([]byte, 8+len(body))
	copy(reply[0:4], evt.Plaintext[0:4]) // echo the sender timestamp
	binary.LittleEndian.PutUint32(reply[4:8], nowTS)
	copy(reply[8:], body)

	rc := evt.Reply
	if len(path) > 0 {
		rc.DirectPath = path
		rc.DirectPathLen = evt.Plaintext[5]
	}
	if err := n.base.SendReply(rc, evt.From, codec.PayloadTypeResponse, reply); err != nil {
		n.log.Warn("failed to send anon response", "error", err)
	}
}

// anonRegionsPayload returns the comma-separated names of regions that permit
// flooding (firmware exports the non-DENY_FLOOD set).
func (n *RepeaterNode) anonRegionsPayload() []byte {
	rm := n.base.Router.RegionMap()
	if rm == nil {
		return nil
	}
	return []byte(rm.ExportNames(router.RegionDenyFlood, false))
}

// anonOwnerPayload returns "name\nowner_info" (firmware's owner reply body).
func (n *RepeaterNode) anonOwnerPayload() []byte {
	return []byte(n.appData.Name + "\n" + n.cfg.OwnerInfo)
}

// anonClockPayload returns a single features byte. Bit 0x80 marks forwarding
// disabled; the bridge bits (0x01/0x03) are N/A for a transport-attached node.
func (n *RepeaterNode) anonClockPayload() []byte {
	var features byte
	if !n.base.Router.GetForwardPackets() {
		features = 0x80
	}
	return []byte{features}
}

// parseAnonReplyPath decodes the {path-len-byte}{path} a client includes in a
// typed anon request, returning the raw path bytes. The length byte encodes the
// hop count (low 6 bits) and hash size (top 2 bits + 1).
func parseAnonReplyPath(data []byte) ([]byte, bool) {
	if len(data) < 1 {
		return nil, false
	}
	need := codec.PathInfoFromWireByte(data[0]).ByteLen()
	if len(data) < 1+need {
		return nil, false
	}
	return data[1 : 1+need], true
}
